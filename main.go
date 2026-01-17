package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"github.com/gin-gonic/gin"
	"google.golang.org/api/option"
)

type GroqResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type RankedPost struct {
    ID    string                 `json:"id"`
    Data  map[string]interface{} `json:"data"`
    Score int                    `json:"score"`
}
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "https://chat-145af.web.app")// Chỉ cho phép cổng React của bạn
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}


func main() {
    cld, _ := cloudinary.NewFromURL(os.Getenv("CLOUDINARY_URL"))
	ctx := context.Background()

	// 1. Khai báo cấu hình với Project ID (Lấy từ Firebase Console của bạn)
	conf := &firebase.Config{ProjectID: "pingme-269"} // Thay "your-project-id-xyz" bằng ID thật của bạn

	// 2. Kết nối với file JSON Key
	sa := option.WithCredentialsFile("serviceAccountKey.json")
	
	// Truyền conf vào thay vì để nil
	app, err := firebase.NewApp(ctx, conf, sa)
	if err != nil {
		log.Fatalf("Lỗi khởi tạo Firebase App: %v", err)
	}

	client, err := app.Firestore(ctx)
	if err != nil {
		log.Fatalf("Lỗi kết nối Firestore: %v", err)
	}
	defer client.Close()

	// 2. Cấu hình Router với Gin
	r := gin.Default()


	r.Use(CORSMiddleware())

	r.POST("/upload", func(c *gin.Context) {
        file, _, err := c.Request.FormFile("file")
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Không tìm thấy file"})
            return
        }

        // Upload lên Cloudinary
        uploadResult, err := cld.Upload.Upload(ctx, file, uploader.UploadParams{
            Folder: "pinggo_profiles",
        })

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi upload lên Cloudinary"})
            return
        }

        // Trả về URL ảnh để React lưu vào Firestore
        c.JSON(http.StatusOK, gin.H{
            "url": uploadResult.SecureURL,
        })
    })
	
	// API Ping thử nghiệm
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Backend PingGo đang chạy!",
		})
	})

	// API lấy danh sách bài viết (Placeholder)
	r.GET("/posts", func(c *gin.Context) {
		// Logic lấy data từ Firestore sẽ viết ở đây
		c.JSON(http.StatusOK, []string{"Bài viết 1", "Bài viết 2"})
	})

	// API Like/Unlike bài viết
r.POST("/posts/:id/like", func(c *gin.Context) {
    postID := c.Param("id")
    var req struct {
        UID string `json:"uid"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
        return
    }

    // Sử dụng context từ request để an toàn hơn
    postRef := client.Collection("posts").Doc(postID)
    docSnap, err := postRef.Get(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Không tìm thấy bài viết"})
        return
    }

    // KIỂM TRA AN TOÀN: Nếu chưa có ai Like, khởi tạo mảng rỗng
    var likesArr []interface{}
    if val, err := docSnap.DataAt("likes"); err == nil && val != nil {
        likesArr = val.([]interface{})
    }

    isLiked := false
    for _, v := range likesArr {
        if v.(string) == req.UID {
            isLiked = true
            break
        }
    }

    var update firestore.Update
    if isLiked {
        update = firestore.Update{Path: "likes", Value: firestore.ArrayRemove(req.UID)}
    } else {
        update = firestore.Update{Path: "likes", Value: firestore.ArrayUnion(req.UID)}
    }

    _, err = postRef.Update(c.Request.Context(), []firestore.Update{update})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi cập nhật Firestore"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Thành công", "isLiked": !isLiked})
})
	
r.POST("/posts/:id/comment", func(c *gin.Context) {
    postID := c.Param("id")
    var req struct {
        UID      string `json:"uid"`
        Username string `json:"username"`
        Avatar   string `json:"avatar"`
        Text     string `json:"text"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
        return
    }

    // 1. Cập nhật số lượng bình luận trong tài liệu Post chính
    postRef := client.Collection("posts").Doc(postID)
    _, err := postRef.Update(c.Request.Context(), []firestore.Update{
        {Path: "commentsCount", Value: firestore.Increment(1)},
    })

    // 2. Thêm bình luận vào bộ sưu tập con "comments" của Post đó
    _, _, err = postRef.Collection("comments").Add(ctx, map[string]interface{}{
        "uid":       req.UID,
        "username":  req.Username,
        "avatar":    req.Avatar,
        "text":      req.Text,
        "createdAt": firestore.ServerTimestamp,
    })

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi lưu bình luận"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Đã thêm bình luận thành công"})
})

// Thêm import "firebase.google.com/go/v4/auth" vào phần import nếu chưa có

r.GET("/get-pingme-token", func(c *gin.Context) {
    uid := c.Query("uid")
    if uid == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Thiếu UID"})
        return
    }

    // Khởi tạo Firebase Auth client
    authClient, err := app.Auth(ctx)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi Auth Client"})
        return
    }

    // Tạo Custom Token dựa trên UID
    token, err := authClient.CustomToken(ctx, uid)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi tạo Token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": token})
})
// API Tìm kiếm bài viết nâng cao với AI Groq
r.GET("/posts/search", func(c *gin.Context) {
    queryText := c.Query("q")
    
    // 1. Nếu không có từ khóa, trả về ngay lập tức
    if queryText == "" {
        c.JSON(http.StatusOK, gin.H{
            "query_used":  "",
            "ai_keywords": []string{},
            "results":     []RankedPost{},
        })
        return
    }

    // 2. Mở rộng từ khóa bằng Groq (Sử dụng hàm expandQueryWithGroq bạn đã viết)
    // Không cần truyền ctx vì Groq dùng http client riêng trong hàm của bạn
    aiKeywords := expandQueryWithGroq(queryText)
    log.Printf("Groq mở rộng từ khóa cho '%s': %v", queryText, aiKeywords)

    // 3. Lấy tất cả bài viết Public từ Firestore
    postsRef := client.Collection("posts").Where("privacy", "==", "public")
    docs, err := postsRef.Documents(ctx).GetAll()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi truy vấn bài viết"})
        return
    }

    var results []RankedPost
    q := strings.ToLower(queryText)

    // 4. Duyệt bài viết và tính điểm (Ranking)
    for _, doc := range docs {
        post := doc.Data()
        
        // Kiểm tra an toàn để tránh crash nếu thiếu trường content hoặc authorName
        content, okC := post["content"].(string)
        author, okA := post["authorName"].(string)
        if !okC || !okA { continue }

        content = strings.ToLower(content)
        author = strings.ToLower(author)

        score := 0
        // Logic Ranking:
        if strings.Contains(author, q) { score += 10 } // Khớp tên tác giả
        if strings.Contains(content, q) { score += 5 }  // Khớp từ khóa gốc

        // Cộng điểm cho từ khóa AI mở rộng
        for _, kw := range aiKeywords {
            if kw != "" && strings.Contains(content, kw) {
                score += 2
            }
        }

        // Chỉ đưa vào kết quả nếu có điểm (tức là có liên quan)
        if score > 0 {
            results = append(results, RankedPost{
                ID:    doc.Ref.ID,
                Data:  post,
                Score: score,
            })
        }
    }

    // 5. Sắp xếp bài viết có điểm cao nhất lên đầu
    sort.Slice(results, func(i, j int) bool {
        return results[i].Score > results[j].Score
    })

    // 6. Trả về kết quả cuối cùng kèm thông tin AI đã dùng
    c.JSON(http.StatusOK, gin.H{
        "query_used":  queryText,
        "ai_keywords": aiKeywords,
        "results":     results,
    })
})
	// Sửa r.Run(":8080") thành:
port := os.Getenv("PORT")
if port == "" {
    port = "8080" // Chạy local
}
r.Run(":" + port)
}

func expandQueryWithGroq(query string) []string {
	apiKey := os.Getenv("GROQ_API_KEY") // Thay Key của bạn vào đây
	url := "https://api.groq.com/openai/v1/chat/completions"

	// Prompt siêu ngắn gọn để ép Groq trả về đúng định dạng
	prompt := "Liệt kê 5 từ đồng nghĩa tiếng Việt cho từ khóa: '" + query + "'. Chỉ trả về các từ cách nhau bằng dấu phẩy, không giải thích thêm."

	// Tạo payload yêu cầu
	payload := map[string]interface{}{
		"model": "llama-3.1-8b-instant", // Model mạnh nhất hiện tại của Groq
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.5,
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Lỗi gọi Groq API: %v", err)
		return []string{}
	}
	defer resp.Body.Close()

	var groqResp GroqResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return []string{}
	}

	if len(groqResp.Choices) > 0 {
		text := groqResp.Choices[0].Message.Content
		// Sử dụng lại logic tách từ thông minh mà Hải đã có
		cleanText := strings.ReplaceAll(text, ",", " ")
		words := strings.Fields(cleanText)

		var keywords []string
		for _, w := range words {
			trimmed := strings.TrimSpace(strings.ToLower(w))
			if len(trimmed) > 2 {
				keywords = append(keywords, trimmed)
			}
		}
		return keywords
	}

	return []string{}
}