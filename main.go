package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

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

func main() {
	
	e, err := casbin.NewEnforcer("rbac_model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("failed to create enforcer: %v", err)
	}

	if err := e.LoadPolicy(); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}


	r := gin.Default()
	r.Use(Authorize(e))

	// Routes
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