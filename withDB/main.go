package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func toInterfaceSlice(s []string) []interface{} {
    i := make([]interface{}, len(s))
    for idx, v := range s {
        i[idx] = v
    }
    return i
}

// Casbin middleware
func Authorize(e *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {

		user := c.GetHeader("X-User")
		if user == "" {
			user = "anonymous"
		}

		obj := c.FullPath()
		act := c.Request.Method

		ok, err := e.Enforce(user, obj, act)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		c.Next()
	}
}

var Enforcer *casbin.Enforcer

func init() {
	// 1. Connect to PostgreSQL
	dsn := "host=localhost user=postgres password=secret dbname=casbin port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// 2. Create adapter with DB
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		log.Fatalf("failed to create adapter: %v", err)
	}

	// 3. Create enforcer with model.conf and DB adapter
	e, err := casbin.NewEnforcer("rbac_model.conf", adapter)
	if err != nil {
		log.Fatalf("failed to create enforcer: %v", err)
	}

	// 4. Try to load policy from DB
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	// 5. If no policy exists in DB, load from CSV and persist
	policies, err := e.GetPolicy()
	if err != nil {
		log.Fatalf("failed to get policies: %v", err)
	}
	if len(policies) == 0 {
		log.Println("No policy in DB, loading from CSV...")

		// Create a temp enforcer with CSV
		tmpEnforcer, err := casbin.NewEnforcer("rbac_model.conf", "policy.csv")
		if err != nil {
			log.Fatalf("failed to create tmp enforcer: %v", err)
		}
		tmpEnforcer.LoadPolicy()

		policies, err := tmpEnforcer.GetPolicy()
		if err != nil {
			log.Fatalf("failed to get policies from CSV enforcer: %v", err)
		}
		for _, p := range policies {
			_, _ = e.AddPolicy(toInterfaceSlice(p)...)
		}

		groups, err := tmpEnforcer.GetGroupingPolicy()
		if err != nil {
			log.Fatalf("failed to get grouping policies from CSV enforcer: %v", err)
		}
		for _, g := range groups {
			_, _ = e.AddGroupingPolicy(toInterfaceSlice(g)...)
		}

		// Save to DB
		_ = e.SavePolicy()
		log.Println("Policies saved into DB.")
	}

	Enforcer = e
}


func main() {

	r := gin.Default()

	r.Use(Authorize(Enforcer))

	r.GET("/admin", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "Welcome Admin"})
	})

	r.POST("/admin", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "Admin Created Something"})
	})

	r.GET("/data", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "User Data"})
	})

	fmt.Println("Server running at http://localhost:8080")
	r.Run(":8080")
}
