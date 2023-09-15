package config

type Credentials struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"spec"`
}
