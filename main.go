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
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type GroqResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Thêm struct để nhận dữ liệu nhóm
type GroupData struct {
	ID   string                 `json:"id"`
	Data map[string]interface{} `json:"data"`
}

// Thêm struct cho yêu cầu chat
type ChatRequest struct {
	Message string `json:"message"`
}

type RankedPost struct {
    ID    string                 `json:"id"`
    Data  map[string]interface{} `json:"data"`
    Score int                    `json:"score"`
}
type InviteRequest struct {
	SenderID   string   `json:"senderId"`
	SenderName string   `json:"senderName"`
	Avatar     string   `json:"avatar"`
	GroupID    string   `json:"groupId"`
	GroupName  string   `json:"groupName"`
	FriendIDs  []string `json:"friendIds"` // Danh sách UID bạn bè được chọn
}

// main.go
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin) 
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		// SỬA DÒNG NÀY: Thêm X-User-UID vào danh sách cho phép
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-User-UID")
		
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// main.go - Cập nhật lại SecurityShieldMiddleware
func SecurityShieldMiddleware(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" { c.Next(); return }

		start := time.Now()
		ip := c.ClientIP()
		path := c.Request.URL.Path
		ua := c.Request.UserAgent()
		
		// 1. Lấy UID lên đầu tiên để dùng cho các bước sau
		uid := c.GetHeader("X-User-UID") 

        _, err := client.Collection("blacklist").Doc(ip).Get(c)
		if err == nil {
			// TRUYỀN uid VÀO ĐÂY để ghi log kẻ tấn công
			go saveSecurityLog(client, uid, ip, path, 403, ua, time.Since(start).Milliseconds())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "SOC Blocked!"})
			return
		}
		c.Next()

		// 3. Ghi log cho request bình thường (Đảm bảo uid được truyền vào)
		go saveSecurityLog(client, uid, ip, path, c.Writer.Status(), ua, time.Since(start).Milliseconds())
	}
}

// Hàm bổ trợ để Hộp C & D chạy ngầm (không làm chậm App)
func saveSecurityLog(client *firestore.Client, uid string, ip string, path string, status int, ua string, latency int64) {
	_, _, _ = client.Collection("security_logs").Add(context.Background(), map[string]interface{}{
        "uid":       uid,
		"ip":        ip,
		"path":      path,
		"status":    status,
		"latency":   latency,
		"userAgent": ua,
		"createdAt": firestore.ServerTimestamp,
	})
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
    r.Use(SecurityShieldMiddleware(client))

    // ĐĂNG KÝ ROUTE TẠI ĐÂY (Trước dòng r.Run)
    r.GET("/groups/discover", func(c *gin.Context) {
        uid := c.Query("uid")
        if uid == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Thiếu UID"})
            return
        }

        ctx := context.Background() // Đảm bảo có ctx

        // BƯỚC 1: Lấy danh sách tên các nhóm mà Hải đã tham gia
        myGroupsSnap, err := client.Collection("groups").Where("members", "array-contains", uid).Documents(ctx).GetAll()
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi truy vấn nhóm của tôi"})
            return
        }

        var myGroupNames []string
        for _, doc := range myGroupsSnap {
            if name, ok := doc.Data()["name"].(string); ok {
                myGroupNames = append(myGroupNames, name)
            }
        }

        // BƯỚC 2: Dùng AI phân tích sở thích (Keywords)
        interests := "chung"
        if len(myGroupNames) > 0 {
            interests = analyzeInterestsWithGroq(myGroupNames)
        }

        // BƯỚC 3: Lấy tất cả nhóm Công khai (Public)
        allPublicGroupsSnap, err := client.Collection("groups").Where("privacy", "==", "public").Documents(ctx).GetAll()
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi truy vấn nhóm công khai"})
            return
        }
        
        var suggestions []GroupData
        for _, doc := range allPublicGroupsSnap {
            data := doc.Data()
            membersArr, _ := data["members"].([]interface{})
            
            // Kiểm tra nếu Hải chưa có trong nhóm này
            isMember := false
            for _, m := range membersArr {
                if m.(string) == uid {
                    isMember = true
                    break
                }
            }

            if !isMember {
                name := strings.ToLower(data["name"].(string))
                // AI Logic: Nếu tên nhóm chứa từ khóa AI hoặc AI trả về "chung"
                if interests == "chung" || strings.Contains(name, strings.ToLower(interests)) {
                    suggestions = append(suggestions, GroupData{ID: doc.Ref.ID, Data: data})
                }
            }
        }

        if len(suggestions) == 0 {
            count := 0
            for _, doc := range allPublicGroupsSnap {
                if count >= 5 { break }
                data := doc.Data()
                membersArr, _ := data["members"].([]interface{})
                
                isMember := false
                for _, m := range membersArr {
                    if m.(string) == uid { isMember = true; break }
                }
        
                if !isMember {
                    suggestions = append(suggestions, GroupData{ID: doc.Ref.ID, Data: data})
                    count++
                }
            }
        }

        // Trả về kết quả
        c.JSON(http.StatusOK, gin.H{
            "ai_analysis": interests,
            "results":     suggestions,
        })
    })
    // Kích hoạt Hộp A & K chạy ngầm (Analysis Engine)
    go AnalysisWorker(client)
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

    // main.go - Thêm vào trong hàm main()
r.GET("/auth/login-success", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Login event captured"})
})

r.GET("/auth/logout-success", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Logout event captured"})
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

// Trong hàm main(), thêm Route này:
r.POST("/ai/chat", func(c *gin.Context) {
    var req ChatRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
        return
    }

    // ĐỊNH NGHĨA KIẾN THỨC VỀ PINGGO Ở ĐÂY
    systemInstruction := `Bạn là trợ lý ảo độc quyền của mạng xã hội PingGo. 
    Hãy sử dụng kiến thức dưới đây để hướng dẫn người dùng:
    1. Giao diện: PingGo có thanh điều hướng (Navbar) trên cùng, Sidebar trái chứa các lối tắt, Newsfeed ở giữa và Sidebar phải chứa danh sách Người liên hệ.
    2. Đổi ngôn ngữ: Người dùng cần vào Sidebar trái -> Chọn 'Cài đặt & quyền riêng tư' -> Chọn mục 'Ngôn ngữ' -> Chọn các quốc gia như Việt Nam, Mỹ, Trung Quốc, v.v.
    3. Đăng bài: Sử dụng khung 'NguyễnHoàngHải ơi, bạn đang nghĩ gì thế?' ở đầu trang chủ để chia sẻ trạng thái, ảnh hoặc video.
    4. Tìm kiếm: PingGo có tìm kiếm thông minh bằng AI. Người dùng gõ từ khóa vào ô tìm kiếm, AI sẽ tự động mở rộng từ khóa để tìm kết quả chính xác hơn.
    5. Tương tác: Có thể Thích (Like), Bình luận (Comment) và xem danh sách người đã tương tác bằng cách nhấn vào biểu tượng trái tim.
    6. Tính năng khác: Có menu 3 chấm để Ẩn bài viết, Chặn người dùng hoặc Quan tâm (Interest) một ai đó.
    7. Kết nối: Có link dẫn sang app nhắn tin PingMe ở Sidebar trái.
    Luôn trả lời thân thiện, xưng hô là 'PingGo Assistant' và gọi người dùng là 'Hải' hoặc 'bạn'.`

    apiKey := os.Getenv("GROQ_API_KEY")
    url := "https://api.groq.com/openai/v1/chat/completions"

    payload := map[string]interface{}{
        "model": "llama-3.1-8b-instant",
        "messages": []map[string]string{
            {"role": "system", "content": systemInstruction}, // Nạp kiến thức vào đây
            {"role": "user", "content": req.Message},
        },
    }

    jsonData, _ := json.Marshal(payload)
    request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    request.Header.Set("Authorization", "Bearer "+apiKey)
    request.Header.Set("Content-Type", "application/json")

    client := &http.Client{Timeout: 20 * time.Second}
    resp, err := client.Do(request)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi kết nối AI"})
        return
    }
    defer resp.Body.Close()

    var groqResp GroqResponse
    json.NewDecoder(resp.Body).Decode(&groqResp)

    if len(groqResp.Choices) > 0 {
        c.JSON(http.StatusOK, gin.H{"reply": groqResp.Choices[0].Message.Content})
    } else {
        c.JSON(http.StatusOK, gin.H{"reply": "Xin lỗi, AI đang bận xử lý, thử lại sau nhé!"})
    }
})

// 2. THÊM ROUTE NÀY VÀO TRƯỚC r.Run
r.POST("/groups/invite", func(c *gin.Context) {
    var req InviteRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
        return
    }

    // Tạo object lời mời
    inviteData := map[string]interface{}{
        "type":       "GROUP_INVITE",
        "groupId":    req.GroupID,
        "groupName":  req.GroupName,
        "senderId":   req.SenderID,
        "senderName": req.SenderName,
        "avatar":     req.Avatar,
        "timestamp":  time.Now().UnixMilli(), // Go lấy time milliseconds
    }

    ctx := context.Background()
    successCount := 0

    // Duyệt qua danh sách bạn bè và update Firestore của từng người
    for _, friendID := range req.FriendIDs {
        _, err := client.Collection("users").Doc(friendID).Update(ctx, []firestore.Update{
            {
                Path:  "groupInvites",
                Value: firestore.ArrayUnion(inviteData),
            },
        })
        
        if err == nil {
            successCount++
        } else {
            log.Printf("Lỗi gửi mời cho %s: %v", friendID, err)
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Đã gửi lời mời thành công",
        "count":   successCount,
    })
})
	// Sửa r.Run(":8080") thành:
port := os.Getenv("PORT")
if port == "" {
    port = "8080" // Chạy local
}
r.Run(":" + port)
}

// main.go - Nâng cấp AnalysisWorker với tính năng Auto-Ban
func AnalysisWorker(client *firestore.Client) {
	ticker := time.NewTicker(15 * time.Second) // Quét định kỳ 15 giây
	for range ticker.C {
		ctx := context.Background()
		window := time.Now().Add(-5 * time.Minute) // Chỉ quét log trong 5 phút gần nhất

		// Bước 1: Lấy các log mới nhất (Chỉ lọc theo thời gian để tránh lỗi Range Filter)
		iter := client.Collection("security_logs").
			Where("createdAt", ">", window).
			Documents(ctx)

		ipCount := make(map[string]int)
		
		for {
			docSnap, err := iter.Next()
			if err == iterator.Done { break }
			if err != nil { break }
			
			data := docSnap.Data()
			status, _ := data["status"].(int64)
			ip, _ := data["ip"].(string)

			// Bước 2: Chỉ đếm các request có lỗi (Status >= 400)
			if status >= 400 {
				ipCount[ip]++
				
				count := ipCount[ip]

				// NGƯỠNG 1: HIỆN CẢNH BÁO (10 lần)
				if count >= 3 && count < 10  {
					client.Collection("security_alerts").Doc(ip).Set(ctx, map[string]interface{}{
						"ip":        ip,
						"type":      "Brute-force Attempt",
						"count":     count,
						"status":    "pending",
						"updatedAt": firestore.ServerTimestamp,
					}, firestore.MergeAll)
				}

				// NGƯỠNG 2: TỰ ĐỘNG CHẶN (20 lần)
				if count >= 10{
					// 1. Đẩy vào Blacklist
					client.Collection("blacklist").Doc(ip).Set(ctx, map[string]interface{}{
						"ip":        ip,
						"reason":    "Auto-blocked: Excessive security violations",
						"blockedAt": firestore.ServerTimestamp,
					})

					// 2. Cập nhật trạng thái cảnh báo sang 'blocked' để Admin biết
					client.Collection("security_alerts").Doc(ip).Update(ctx, []firestore.Update{
						{Path: "status", Value: "blocked"},
						{Path: "count", Value: count},
						{Path: "updatedAt", Value: firestore.ServerTimestamp},
					})
					
					log.Printf("🛡️  SYSTEM: IP %s has been AUTO-BLOCKED after %d violations.", ip, count)
				}
			}
		}
	}
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

// 2. Hàm AI phân tích sở thích
func analyzeInterestsWithGroq(groupNames []string) string {
apiKey := os.Getenv("GROQ_API_KEY")
	url := "https://api.groq.com/openai/v1/chat/completions"

	prompt := "Dựa trên danh sách các nhóm sau: '" + strings.Join(groupNames, ", ") + "'. Hãy đưa ra 1 chủ đề chính ngắn gọn (1-2 từ) mô tả sở thích của người này (VD: Công nghệ, Bóng đá, Học tập). Chỉ trả về đúng từ đó."

	payload := map[string]interface{}{
		"model": "llama-3.1-8b-instant",
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	}

	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{}).Do(req)
	if err != nil { return "chung" }
	defer resp.Body.Close()

	var groqResp GroqResponse
	json.NewDecoder(resp.Body).Decode(&groqResp)
	if len(groqResp.Choices) > 0 {
		return strings.TrimSpace(groqResp.Choices[0].Message.Content)
	}
	return "chung"
}
