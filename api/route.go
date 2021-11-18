package api

import (
	"github.com/fs714/goiftop/api/v1"
	"github.com/fs714/goiftop/utils/config"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

func InitRouter() *gin.Engine {
	gin.SetMode("release")
	gin.DisableConsoleColor()
	r := gin.New()
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/api/v1/health"},
	}))
	r.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithDecompressFn(gzip.DefaultDecompressHandle)))
	r.Use(gin.Recovery())
	r.Use(cors.Default())

	if config.IsProfiling {
		pprof.Register(r)
	}

	apiv1 := r.Group("/api/v1")
	{
		apiv1.GET("/health", v1.Health)
	}

	return r
}
