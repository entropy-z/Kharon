package main

import(
	"github.com/gin-gonic/gin"
	"net/http"
	// "golang.org/x/net/context"
)

type OutputConfig struct {
	Mask      bool   
	Header    string 
	Format    string 
	Parameter string 
	Cookie    string
	Body      string 

	Append  string
	Prepend string

	MaxDataSize int
}

type URIConfig struct {
	ServerOutput *OutputConfig
	ClientOutput *OutputConfig
	ClientParams []map[string]interface{}
}

type ServerError struct {
	Status   int   
	Response string
	Headers  map[string]string    
}

type HTTPMethod struct {
	ServerHeaders map[string]string    
	EmptyResponse []byte               
	ClientHeaders map[string]string    
	URI           map[string]URIConfig 
}

type Callback struct {
	Hosts      	  []string 		
	Host      	  string 	
	UserAgent 	  string      	
	SrvError      *ServerError 
	Get       	  *HTTPMethod 
	Post          *HTTPMethod 
}

type HttpTask struct {
	RequestId int
	TaskId    int
	MaxSize   int
	MissingChunkCount int

	Buffer 		 []byte
	CurrentIndex int
}

type HTTPConfig struct {
	HostBind   string `json:"host_bind"`
	PortBind   int    `json:"port_bind"`

	BlockUserAgent string `json:"block_user_agents"`
	ProfileContent string `json:"uploaded_file"`

	DomainRotation string `json:"domain_rotation_strategy"`

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	// CryptKey []byte `json:"encrypt_key"`

	Protocol   string `json:"protocol"`
	EncryptKey []byte `json:"encrypt_key"`
	MaskKey    []byte  

	ProxyUrl      string `json:"proxy_url"`
	ProxyUserName string `json:"proxy_user"`
	ProxyPassword string `json:"proxy_pass"`

	ChunkTask []HttpTask

	Addresses 	string
	Callbacks   []Callback
}

type HTTP struct {
	GinEngine *gin.Engine
	Server    *http.Server
	Config    HTTPConfig
	Name      string
	Active    bool
}

type ServerRequest struct {
	Headers		string
	Body    	[]byte
	EmptyResp	[]byte
	Payload     []byte
}

type ClientRequest struct {
	Uri  		string
	HttpMethod	string
	Address     string
	Params      map[string][]string
	UserAgent   string
	Body 		[]byte
	Payload     []byte

	Config      Callback

	UriConfig       *URIConfig
	HttpMethodCfg	*HTTPMethod
}