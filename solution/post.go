package solution

type RequestChangePass struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}
type Pagination struct {
	Limit  string `json:"paginationLimit"`
	Offset string `json:"paginationOffset"`
}
type Posts struct {
	Content   string   `json:"content"`
	Tags      []string `json:"tags"`
	VideoLink string   `json:"videoLink"`
}
type PostResponse struct {
	Id            string   `json:"id"`
	Content       string   `json:"content"`
	Author        string   `json:"author"`
	Tags          []string `json:"tags"`
	VideoLink     string   `json:"videoLink"`
	CreatedAt     string   `json:"createdAt"`
	LikesCount    int      `json:"likesCount"`
	DislikesCount int      `json:"dislikesCount"`
}
type FindPrefix struct {
	Prefix string `json:"prefix"`
}
