package config

// Dns ...
type Dns struct {
	IP             string `json:"ip"`
	Port           string `json:"port"`
	Dbname         string `json:"dbname"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Max_idle_conns int    `json:"max_idle_conns"`
	Max_open_conns int    `json:"max_open_conns"`
}
