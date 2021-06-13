package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

var CipherKey = "JumpServer Cipher Key for KoKo !"

type Config struct {
	Name           string `mapstructure:"NAME"`
	CoreHost       string `mapstructure:"CORE_HOST"`
	BootstrapToken string `mapstructure:"BOOTSTRAP_TOKEN"`
	BindHost       string `mapstructure:"BIND_HOST"`
	SSHPort        string `mapstructure:"SSHD_PORT"`
	HTTPPort       string `mapstructure:"HTTPD_PORT"`
	SSHTimeout     int    `mapstructure:"SSH_TIMEOUT"`

	LogLevel            string `mapstructure:"LOG_LEVEL"`
	RootPath            string `mapstructure:"ROOT_PATH"`
	Comment             string `mapstructure:"COMMENT"`
	LanguageCode        string `mapstructure:"LANGUAGE_CODE"`
	UploadFailedReplay  bool   `mapstructure:"UPLOAD_FAILED_REPLAY_ON_START"`
	AssetLoadPolicy     string `mapstructure:"ASSET_LOAD_POLICY"` // all
	ZipMaxSize          string `mapstructure:"ZIP_MAX_SIZE"`
	ZipTmpPath          string `mapstructure:"ZIP_TMP_PATH"`
	ClientAliveInterval int    `mapstructure:"CLIENT_ALIVE_INTERVAL"`
	RetryAliveCountMax  int    `mapstructure:"RETRY_ALIVE_COUNT_MAX"`
	ShowHiddenFile      bool   `mapstructure:"SFTP_SHOW_HIDDEN_FILE"`
	ReuseConnection     bool   `mapstructure:"REUSE_CONNECTION"`

	ShareRoomType string   `mapstructure:"SHARE_ROOM_TYPE"`
	RedisHost     string   `mapstructure:"REDIS_HOST"`
	RedisPort     string   `mapstructure:"REDIS_PORT"`
	RedisPassword string   `mapstructure:"REDIS_PASSWORD"`
	RedisDBIndex  int      `mapstructure:"REDIS_DB_ROOM"`
	RedisClusters []string `mapstructure:"REDIS_CLUSTERS"`

	EnableLocalPortForward bool `mapstructure:"ENABLE_LOCAL_PORT_FORWARD"`
	EnableVscodeSupport    bool `mapstructure:"ENABLE_VSCODE_SUPPORT"`

	DataFolderPath    string
	LogDirPath        string
	KeyFolderPath     string
	AccessKeyFilePath string
	ReplayFolderPath  string
}

func (c *Config) EnsureConfigValid() {
	if c.LanguageCode == "" {
		c.LanguageCode = "zh"
	}
}

//func (c *Config) LoadFromYAML(body []byte) error {
//	err := yaml.Unmarshal(body, c)
//	if err != nil {
//		log.Printf("Load yaml error: %v", err)
//	}
//	return err
//}
//
//func (c *Config) LoadFromYAMLPath(filepath string) error {
//	body, err := ioutil.ReadFile(filepath)
//	if err != nil {
//		log.Printf("Not found file: %s", filepath)
//		return err
//	}
//	return c.LoadFromYAML(body)
//}
//
//func (c *Config) LoadFromJSON(body []byte) error {
//	err := json.Unmarshal(body, c)
//	if err != nil {
//		log.Printf("Config load yaml error")
//	}
//	return nil
//}

//func (c *Config) LoadFromEnv() error {
//	envMap := make(map[string]string)
//	env := os.Environ()
//	for _, v := range env {
//		vSlice := strings.SplitN(v, "=", 1)
//		key := vSlice[0]
//		value := vSlice[1]
//		// 环境变量的值，非字符串类型的解析，需要另作处理
//		switch key {
//		case "SFTP_SHOW_HIDDEN_FILE", "REUSE_CONNECTION", "UPLOAD_FAILED_REPLAY_ON_START":
//			switch strings.ToLower(value) {
//			case "true", "on":
//				switch key {
//				case "SFTP_SHOW_HIDDEN_FILE":
//					c.ShowHiddenFile = true
//				case "REUSE_CONNECTION":
//					c.ReuseConnection = true
//				case "UPLOAD_FAILED_REPLAY_ON_START":
//					c.UploadFailedReplay = true
//				}
//			case "false", "off":
//				switch key {
//				case "SFTP_SHOW_HIDDEN_FILE":
//					c.ShowHiddenFile = false
//				case "REUSE_CONNECTION":
//					c.ReuseConnection = false
//				case "UPLOAD_FAILED_REPLAY_ON_START":
//					c.UploadFailedReplay = false
//				}
//			}
//		case "SSH_TIMEOUT":
//			if num, err := strconv.Atoi(value); err == nil {
//				c.SSHTimeout = time.Duration(num)
//			}
//		case "REDIS_CLUSTERS":
//			clusters := strings.Split(value, ",")
//			c.RedisClusters = clusters
//		default:
//			envMap[key] = value
//		}
//	}
//	envYAML, err := yaml.Marshal(&envMap)
//	if err != nil {
//		log.Fatalf("Error occur: %v", err)
//	}
//	return c.LoadFromYAML(envYAML)
//}

//func (c *Config) Load(filepath string) error {
//	var err error
//	log.Print("Config Load from env first")
//	_ = c.LoadFromEnv()
//	if _, err = os.Stat(filepath); err == nil {
//		log.Printf("Config reload from file: %s", filepath)
//		return c.LoadFromYAMLPath(filepath)
//	}
//	return nil
//}

func GetConf() Config {
	return *GlobalConfig
}

var GlobalConfig *Config

func Setup(configPath string) {
	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()
	loadEnvToViper()
	log.Println("Load config from env")
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Load config from %s success\n", configPath)
	}
	var conf = getDefaultConfig()
	if err := viper.Unmarshal(&conf); err != nil {
		log.Fatal(err)
	}
	conf.EnsureConfigValid()
	GlobalConfig = &conf
	log.Printf("%+v\n", GlobalConfig)

}

func getDefaultConfig() Config {
	defaultName := getDefaultName()
	rootPath := getPwdDirPath()
	dataFolderPath := filepath.Join(rootPath, "data")
	replayFolderPath := filepath.Join(dataFolderPath, "replays")
	LogDirPath := filepath.Join(dataFolderPath, "logs")
	keyFolderPath := filepath.Join(dataFolderPath, "keys")
	accessKeyFilePath := filepath.Join(keyFolderPath, ".access_key")

	folders := []string{dataFolderPath, replayFolderPath, keyFolderPath, LogDirPath}
	for i := range folders {
		if err := EnsureDirExist(folders[i]); err != nil {
			log.Fatalf("Create folder failed: %s", err)
		}
	}
	return Config{
		Name:              defaultName,
		CoreHost:          "http://localhost:8080",
		BootstrapToken:    "",
		BindHost:          "0.0.0.0",
		SSHPort:           "2222",
		SSHTimeout:        15,
		HTTPPort:          "5000",
		AccessKeyFilePath: accessKeyFilePath,
		LogLevel:          "INFO",
		RootPath:          rootPath,
		DataFolderPath:    dataFolderPath,
		LogDirPath:        LogDirPath,
		KeyFolderPath:     keyFolderPath,
		ReplayFolderPath:  replayFolderPath,

		Comment:             "KOKO",
		UploadFailedReplay:  true,
		ShowHiddenFile:      false,
		ReuseConnection:     true,
		AssetLoadPolicy:     "",
		ZipMaxSize:          "1024M",
		ZipTmpPath:          "/tmp",
		ClientAliveInterval: 30,
		RetryAliveCountMax:  3,
		ShareRoomType:       "local",
		RedisHost:           "127.0.0.1",
		RedisPort:           "6379",
		RedisPassword:       "",

		EnableLocalPortForward: false,
		EnableVscodeSupport:    false,
	}

}

func EnsureDirExist(path string) error {
	if !haveDir(path) {
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

func haveDir(file string) bool {
	fi, err := os.Stat(file)
	return err == nil && fi.IsDir()
}

func getPwdDirPath() string {
	if rootPath, err := os.Getwd(); err == nil {
		return rootPath
	}
	return ""
}

func loadEnvToViper() {
	for _, item := range os.Environ() {
		envItem := strings.SplitN(item, "=", 2)
		if len(envItem) == 2 {
			viper.Set(envItem[0], envItem[1])
		}
	}
}

const prefixName = "[KoKo]"

func getDefaultName() string {
	hostname, _ := os.Hostname()
	hostRune := []rune(prefixName + hostname)
	if len(hostRune) <= 32 {
		return string(hostRune)
	}
	name := make([]rune, 32)
	copy(name[:16], hostRune[:16])
	start := len(hostRune) - 16
	copy(name[16:], hostRune[start:])
	return string(name)
}
