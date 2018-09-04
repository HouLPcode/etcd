package main

import (
	"testing"
	"net/http"
	"log"
	"time"
	"io/ioutil"
)

type mhttp struct { }

//浏览器输入地址 localhost:1200进行测试
func TestHttp(t *testing.T){
	t.Log("hello baby")
	srv := http.Server{
		Addr: ":1200",
		Handler: &mhttp{},
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	for ; ;  {
		time.Sleep(time.Second)
	}

}


//curl -L http://127.0.0.1:1200/my-key -XGET -d world
//method is GETkey is /my-keybody is world
func (mhttp)ServeHTTP(w http.ResponseWriter,r *http.Request) {
	w.Write([]byte("method is " + r.Method))
	w.Write([]byte("key is " + r.RequestURI))

	v,err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read on PUT (%v)\n", err)
		http.Error(w, "Failed on PUT", http.StatusBadRequest)
		return
	}
	buf := make([]byte,1024)
	copy(buf,[]byte("body is "))
	copy(buf[8:],v)
	w.Write(buf[:8+len(v)])

	//switch {
	//case r.Method == "PUT":
	//	v, err := ioutil.ReadAll(r.Body)
	//
	//	w.Write([]byte("method is PUT " + r.RequestURI))
	//	w.WriteHeader(http.StatusNoContent)
	//case r.Method == "GET":
	//	w.Write([]byte("method is GET"))
	//case r.Method == "POST":
	//	w.Write([]byte("method is POST"))
	//	// As above, optimistic that raft will apply the conf change
	//	w.WriteHeader(http.StatusNoContent)
	//case r.Method == "DELETE":
	//	w.Write([]byte("method is DELETE"))
	//	// As above, optimistic that raft will apply the conf change
	//	w.WriteHeader(http.StatusNoContent)
	//default:
	//	w.Header().Set("Allow", "PUT")
	//	w.Header().Add("Allow", "GET")
	//	w.Header().Add("Allow", "POST")
	//	w.Header().Add("Allow", "DELETE")
	//	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	//}
}