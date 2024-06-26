package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	capi "github.com/hashicorp/consul/api"
	"github.com/syndtr/goleveldb/leveldb"
)

type appConfig struct {
	LevelDBLocation string `yaml:"LevelDBLocation"`
	EncryptionKey   string `yaml:"EncryptionKey"`
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

func postACL(tokens *Set, db *leveldb.DB, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		var newACL fdasACL
		// Output request text
		fmt.Println(c.Request.Body)
		err := c.BindJSON(&newACL)
		object := strings.ReplaceAll(newACL.Object, "/", "")
		relation := strings.ReplaceAll(newACL.Relation, "/", "")
		user := strings.ReplaceAll(newACL.User, "/", "")

		if err != nil || object == "" || relation == "" || user == "" {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL definition"})
			panic(err)
			return
		}
		objectParts := strings.SplitN(object, ":", 2)
		if len(objectParts) != 2 {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL object definition"})
			return
		}
		namespace := objectParts[0]
		pair, _, err := kv.Get(namespace, nil)
		if err != nil || pair == nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid ACL namespace"})
			return
		}
		availableRelations := strings.Split(string(pair.Value), ",")
		if !checkIfRelationValid(relation, &availableRelations) {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "ACL relation not supported in this namespace"})
			return
		}

		err = db.Put([]byte(user+"/"+object), []byte(relation), nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Putting items in levelDB\", \"method\": \"postACL\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.IndentedJSON(http.StatusCreated, newACL)

	}
}

func checkACL(tokens *Set, db *leveldb.DB, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		object := c.Query("object")
		relation := c.Query("relation")
		user := c.Query("user")

		if object == "" || relation == "" || user == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid ACL request, empty string"})
			return
		}
		parts := strings.SplitN(object, ":", 2)
		if len(parts) != 2 {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid ACL object definition"})
			return
		}

		data, err := db.Get([]byte(user+"/"+object), nil)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "ACL not found"})
			return
		}
		if bytes.Equal(data, []byte(relation)) {
			c.JSON(http.StatusOK, gin.H{"authorized": true})
			return
		}

		namespace := parts[0]
		s := hashSHA256(string(data) + "/" + relation)
		value, _, err := kv.Get(namespace+"/"+s, nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Checking if relation is valid\", \"method\": \"checkACL\"}")
			c.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"authorized": value != nil})

	}
}

func postNamespace(tokens *Set, kv *capi.KV) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tokens.Has(c.Param("token")) {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			return
		}
		var newNamespace fdasConfig
		if err := c.BindJSON(&newNamespace); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid namespace definition"})
			return
		}
		namespace := strings.ReplaceAll(newNamespace.Namespace, "/", "")
		if namespace == "" {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid namespace definition, using empty string"})
			return
		}

		relatshionshipMap := make(map[string][]string)
		allRelations := ""
		pair, _, err := kv.Get(namespace, nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Getting items from consul\", \"method\": \"postNamespace\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}
		var oldKeys []string
		var oldValues [][]byte
		if pair != nil {
			oldKeys, _, err = kv.Keys(namespace, "", nil)
			if err != nil {
				log.Fatalf("{\"error\": \"Reading keys from consul\", \"method\": \"postNamespace\"}")
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
				return
			}
			for _, key := range oldKeys {
				value, _, err := kv.Get(key, nil)
				if err != nil {
					log.Fatalf("{\"error\": \"Reading values from consul\", \"method\": \"postNamespace\"}")
					c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
					return
				}
				oldValues = append(oldValues, value.Value)
				kv.Delete(key, nil)
			}
		}

		for key, value := range newNamespace.Relations {
			key = strings.ReplaceAll(key, "/", "")
			if key == "" {
				c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "invalid namespace definition, using empty key"})
				// Roll-back kv.Delete(key, nil)
				for index, key := range oldKeys {
					kv.Put(&capi.KVPair{Key: key, Value: oldValues[index]}, nil)
				}
				return
			}

			if allRelations == "" {
				allRelations = key
			} else {
				allRelations += "," + key
			}

			relatshionshipMap[key] = value.Union

			for _, item := range value.Union {
				if _, ok := relatshionshipMap[item]; !ok {
					c.IndentedJSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("invalid namespace definition, using role %s before defining it", item)})
					// Roll-back kv.Delete(key, nil)
					for i := range oldKeys {
						kv.Put(&capi.KVPair{Key: oldKeys[i], Value: oldValues[i]}, nil)
					}
					return
				}
			}

			err = createRelations(namespace, key, value.Union, &relatshionshipMap, kv)
			if err != nil {
				log.Fatalf("{\"error\": \"Creating relatshionships in consul\", \"method\": \"postNamespace\"}")
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
				return
			}
		}

		p := &capi.KVPair{Key: namespace, Value: []byte(allRelations)}
		_, err = kv.Put(p, nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Putting items in levelDB\", \"method\": \"postNamespace\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		c.IndentedJSON(http.StatusCreated, newNamespace)
	}
}

func getToken(encryptionKey string, tokens *Set, db *leveldb.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokensString string
		id := strings.ReplaceAll(uuid.New().String(), "-", "")
		tokens.Add(id)
		data, err := db.Get([]byte("tokens"), nil)
		if err != nil {
			tokensString = id
		} else {
			tokensString = string(data) + "," + id
		}

		tokensEncrypted, err := encrypt([]byte(tokensString), []byte(encryptionKey))
		if err != nil {
			log.Fatalf("{\"error\": \"Encrypting tokens\", \"method\": \"getToken\"}")
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
			return
		}

		err = db.Put([]byte("tokens"), tokensEncrypted, nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Putting new user token in levelDB\", \"method\": \"getToken\"}")
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
			log.Fatalf("{\"error\": \"Putting other tokens in levelDB\", \"method\": \"invalidateToken\"}")
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
	consulConfig := capi.DefaultConfig()
	consulAddress := os.Getenv("CONSUL_ADDRESS")
	if consulAddress == "" {
		consulAddress = "localhost:8500" // Default value
	}
	consulConfig.Address = consulAddress
	consulClient, err := capi.NewClient(consulConfig)
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
	tokens := loadTokens(levelDB, appConfig.EncryptionKey)

	// GIN API
	router := gin.Default()
	router.GET("/api/token", getToken(appConfig.EncryptionKey, tokens, levelDB))
	router.PUT("/api/invalidate/:token", invalidateToken(tokens, levelDB))
	router.POST("/api/namespace/:token", postNamespace(tokens, consulKV))
	router.POST("/api/acl/:token", postACL(tokens, levelDB, consulKV))
	router.GET("/api/acl/check/:token", checkACL(tokens, levelDB, consulKV))

	router.Run("0.0.0.0:8080")
}

func loadTokens(db *leveldb.DB, encryptionKey string) *Set {
	allIssuedTokens := NewSet()
	data, err := db.Get([]byte("tokens"), nil)

	if err == nil {
		tokens, err := decrypt(data, []byte(encryptionKey))
		if err != nil {
			panic(err)
		}
		allIssuedTokens.AddMulti(strings.Split(string(tokens), ",")...)
	}

	return allIssuedTokens
}

func createRelations(namespace string, key string, unionItems []string, relatshionshipMap *map[string][]string, kv *capi.KV) error {
	var err error
	for _, parent := range unionItems {
		parent = strings.ReplaceAll(parent, "/", "")
		s := hashSHA256(parent + "/" + key)
		p := &capi.KVPair{Key: namespace + "/" + s, Value: []byte{}}
		_, err = kv.Put(p, nil)
		if err != nil {
			log.Fatalf("{\"error\": \"Critical while putting items in consul\", \"method\": \"createRelations\"}")
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

func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func encrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	nonce, err := generateRandomBytes(aesGCM.NonceSize())
	if err != nil {
		return []byte{}, err
	}

	cipherText := aesGCM.Seal(nonce, nonce, plainText, nil)
	return cipherText, nil
}

func decrypt(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherText) < nonceSize {
		return []byte{}, fmt.Errorf("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return []byte{}, err
	}

	return plainText, nil
}
