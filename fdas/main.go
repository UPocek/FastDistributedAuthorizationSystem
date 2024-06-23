package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	capi "github.com/hashicorp/consul/api"
	"github.com/syndtr/goleveldb/leveldb"
	"gopkg.in/yaml.v3"
)

// Structs

type appConfig struct {
	LevelDBLocation string `yaml:"LevelDBLocation"`
}

type fdasRelations struct {
	Union []string `json:"union"`
}

type fdasConfig struct {
	Namespace string                    `json:"namespace"`
	Relations map[string]*fdasRelations `json:"relations"`
}

type fdasACL struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
	User     string `json:"user"`
}

type Set struct {
	list map[string]struct{}
}

func (s *Set) Has(v string) bool {
	_, ok := s.list[v]
	return ok
}

func (s *Set) Add(v string) {
	s.list[v] = struct{}{}
}

func (s *Set) Remove(v string) {
	delete(s.list, v)
}

func (s *Set) Clear() {
	s.list = make(map[string]struct{})
}

func (s *Set) Size() int {
	return len(s.list)
}

func NewSet() *Set {
	s := &Set{}
	s.list = make(map[string]struct{})
	return s
}

func (s *Set) AddMulti(list ...string) {
	for _, v := range list {
		s.Add(v)
	}
}

func (s *Set) Keys() []string {
	keys := make([]string, 0, s.Size())
	for k := range s.list {
		keys = append(keys, k)
	}
	return keys
}

// Endpoints

func postACL(tokens *Set, db *leveldb.DB, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		var newACL fdasACL
		if err := c.BindJSON(&newACL); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL definition"})
			return
		}
		parts := strings.Split(newACL.Object, ":")
		if len(parts) != 2 {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL object definition"})
			return
		}
		namespace := parts[0]
		pair, _, err := kv.Get(namespace, nil)
		if err != nil || pair == nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL namespace"})
			return
		}
		availableRelations := strings.Split(string(pair.Value), ",")
		if !checkIfRelationValid(newACL.Relation, &availableRelations) {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "ACL relation not supported in this namespace"})
			return
		}

		err = db.Put([]byte(newACL.User+"/"+newACL.Object), []byte(newACL.Relation), nil)
		if err != nil {
			fmt.Println("{\"error\": \"Putting items in levelDB\", \"method\": \"postACL\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.IndentedJSON(http.StatusCreated, newACL)

	}
}

func checkACL(tokens *Set, db *leveldb.DB, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		object := c.Query("object")
		relation := c.Query("relation")
		user := c.Query("user")

		if object == "" || relation == "" || user == "" {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL request"})
			return
		}

		data, err := db.Get([]byte(user+"/"+object), nil)
		if err != nil {
			c.IndentedJSON(http.StatusNotFound, gin.H{"message": "ACL not found"})
			return
		}
		if string(data) == relation {
			c.IndentedJSON(http.StatusOK, true)
			return
		}
		parts := strings.Split(object, ":")
		if len(parts) != 2 {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL object definition"})
			return
		}
		namespace := parts[0]
		value, _, err := kv.Get(namespace+"/"+string(data)+"/"+relation, nil)
		if err == nil || value != nil {
			c.IndentedJSON(http.StatusOK, true)
		} else {
			c.IndentedJSON(http.StatusOK, false)
		}

	}
}

func postNamespace(tokens *Set, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		var newNamespace fdasConfig
		relatshionshipMap := make(map[string][]string)
		allRelations := ""
		if err := c.BindJSON(&newNamespace); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid namespace definition"})
			return
		}
		pair, _, err := kv.Get(newNamespace.Namespace, nil)
		if err != nil {
			fmt.Println("{\"error\": \"Getting items from consul\", \"method\": \"postNamespace\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}
		if pair != nil {
			keys, _, err := kv.Keys(newNamespace.Namespace, "", nil)
			if err != nil {
				fmt.Println("{\"error\": \"Reading keys from consul\", \"method\": \"postNamespace\"}")
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
				return
			}
			for _, key := range keys {
				kv.Delete(key, nil)
			}
		}

		for key, value := range newNamespace.Relations {
			if allRelations == "" {
				allRelations = key
			} else {
				allRelations += "," + key
			}
			relatshionshipMap[key] = value.Union

			err = createRelations(newNamespace.Namespace, key, value.Union, &relatshionshipMap, kv)
			if err != nil {
				fmt.Println("{\"error\": \"Creating relatshionships in consul\", \"method\": \"postNamespace\"}")
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
				return
			}
		}

		p := &capi.KVPair{Key: newNamespace.Namespace, Value: []byte(allRelations)}
		_, err = kv.Put(p, nil)
		if err != nil {
			fmt.Println("{\"error\": \"Putting items in levelDB\", \"method\": \"postNamespace\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.IndentedJSON(http.StatusCreated, newNamespace)
	}
}

func getToken(tokens *Set, db *leveldb.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokensString string
		id := uuid.New().String()
		tokens.Add(id)
		data, err := db.Get([]byte("tokens"), nil)
		if err != nil {
			tokensString = id
		} else {
			tokensString = string(data) + "," + id
		}

		err = db.Put([]byte("tokens"), []byte(tokensString), nil)
		if err != nil {
			fmt.Println("{\"error\": \"Putting new user token in levelDB\", \"method\": \"getToken\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.IndentedJSON(200, gin.H{"token": id})
	}
}

func invalidateToken(tokens *Set, db *leveldb.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokens.Remove(c.Param("token"))

		tokensString := strings.Join(tokens.Keys(), ",")

		err := db.Put([]byte("tokens"), []byte(tokensString), nil)
		if err != nil {
			fmt.Println("{\"error\": \"Putting other tokens in levelDB\", \"method\": \"invalidateToken\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

func main() {
	// APP CONFIG
	var appConfig appConfig
	configFile, err := os.ReadFile("./config.yaml")
	if err != nil {
		panic(err)
	}
	yaml.Unmarshal(configFile, &appConfig)

	// ConsulDB SETUP
	consulClient, err := capi.NewClient(capi.DefaultConfig())
	if err != nil {
		panic(err)
	}
	consulKV := consulClient.KV()

	// LEVEL DB SETUP
	levelDB, err := leveldb.OpenFile(appConfig.LevelDBLocation, nil)
	if err != nil {
		panic(err)
	}
	defer levelDB.Close()

	// ISSUED API TOKENS
	tokens := loadTokens(levelDB)

	// GIN API
	router := gin.Default()
	router.GET("/api/token", getToken(tokens, levelDB))
	router.PUT("/api/invalidate/:token", invalidateToken(tokens, levelDB))
	router.POST("/api/namespace/:token", postNamespace(tokens, consulKV))
	router.POST("/api/acl/:token", postACL(tokens, levelDB, consulKV))
	router.GET("/api/acl/check/:token", checkACL(tokens, levelDB, consulKV))

	router.Run("localhost:8080")
}

func loadTokens(db *leveldb.DB) *Set {
	allIssuedTokens := NewSet()
	data, err := db.Get([]byte("tokens"), nil)

	if err == nil {
		allIssuedTokens.AddMulti(strings.Split(string(data), ",")...)
	}

	return allIssuedTokens
}

func createRelations(namespace string, key string, unionItems []string, relatshionshipMap *map[string][]string, kv *capi.KV) error {
	var err error
	for _, parent := range unionItems {
		p := &capi.KVPair{Key: namespace + "/" + parent + "/" + key, Value: []byte{}}
		_, err = kv.Put(p, nil)
		if err != nil {
			fmt.Println("{\"error\": \"Critical while putting items in consul\", \"method\": \"createRelations\"}")
			return err
		}
		if len((*relatshionshipMap)[parent]) != 0 {
			err = createRelations(namespace, key, (*relatshionshipMap)[parent], relatshionshipMap, kv)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func checkIfRelationValid(relation string, allAvailableRelations *[]string) bool {
	for _, availableRelation := range *allAvailableRelations {
		if availableRelation == relation {
			return true
		}
	}
	return false
}
