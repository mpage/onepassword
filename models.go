package onepassword

type Category struct {
	Uuid string
	Name string
}

type ItemOverview struct {
	Title string   `json:"title"`
	Url   string   `json:"url"`
	Tags  []string `json:"tags"`
	Cat   Category
}

type Item struct {
	Overview  ItemOverview
	Details   []byte // JSON encoded object. Structure is based on category.
}
