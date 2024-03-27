package solution

type Country struct {
	Name   string `json:"name" db:"name"`
	Alpha2 string `json:"alpha2" db:"alpha2"`
	Alpha3 string `json:"alpha3" db:"alpha3"`
	Region string `json:"region" db:"region"`
}
type User struct {
	Login       string `json:"login"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	CountryCode string `json:"countryCode"`
	IsPublic    string `json:"isPublic"`
	Phone       string `json:"phone,omitempty"`
	Image       string `json:"image,omitempty"`
}
type ResponseUser struct {
	Login       string `json:"login"`
	Email       string `json:"email"`
	CountryCode string `json:"countryCode"`
	IsPublic    string `json:"isPublic"`
	Phone       string `json:"phone,omitempty"`
	Image       string `json:"image,omitempty"`
}
type AuthUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
type FiendRequest struct {
	Login string `json:"login"`
}
type Friends struct {
	Login2    string `json:"login" db:"login2"`
	CreatedAt string `json:"addedAt"`
}
