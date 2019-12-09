package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"image-bouncer-webhook/rules"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)


type Config struct {
	CertFile string
	KeyFile  string
}

var (
	whitelistNamespaces   = os.Getenv("WHITELIST_NAMESPACES")
	whitelistRegistries   = os.Getenv("WHITELIST_REGISTRIES")
	webhookUrl            = os.Getenv("WEBHOOK_URL")
	whitelistedNamespaces = strings.Split(whitelistNamespaces, ",")
	whitelistedRegistries = strings.Split(whitelistRegistries, ",")
)

type SlackRequestBody struct {
	Text string `json:"text"`
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	klog.Fatalf("Serving Request: %s", r.URL.Path)
	w.WriteHeader(http.StatusOK)
}

func validateAdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	klog.Fatalf("Serving Request: %s", r.URL.Path)
	// set header
	w.Header().Set("Content-Type", "application/json")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		klog.Fatalln(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println(string(data))
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(data, &ar); err != nil {
		klog.Fatalln(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	namespace := ar.Request.Namespace
	klog.Fatalf("AdmissionReview Namespace: %s", namespace)

	admissionResponse := v1beta1.AdmissionResponse{Allowed: false}
	images := make([]string,2)
	initImages := make([]string,2)


	if !rules.IsWhitelistNamespace(whitelistedNamespaces, namespace) {
		pod := v1.Pod{}
		if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
			klog.Fatalln(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Handle InitContainers
		for _, container := range pod.Spec.InitContainers {
			initImages = append(initImages, container.Image)
			usingLatest, err := rules.IsUsingLatestTag(container.Image)
			if err != nil {
				klog.Fatalf("Error while parsing initimage name: %+v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if usingLatest {
				message := fmt.Sprintf("InitContainer Images using latest tag are not allowed" + container.Image)
				SendSlackNotification(message)
				admissionResponse.Result = getInvalidContainerResponse(message)
				goto done
			}
			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					klog.Fatalf("Error while looking for image registry: %+v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !validRegistry {
					message := fmt.Sprintf("InitContainer Image from a non whitelisted Registry" + container.Image)
					SendSlackNotification(message)
					admissionResponse.Result = getInvalidContainerResponse(message)
					goto done
				}
			}
		}

		// Handle Containers
		for _, container := range pod.Spec.Containers {
			images = append(images, container.Image)
			usingLatest, err := rules.IsUsingLatestTag(container.Image)
			if err != nil {
				klog.Fatalf("Error while parsing image name: %+v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if usingLatest {
				message := fmt.Sprintf("Container Images using latest tag are not allowed" + container.Image)
				SendSlackNotification(message)
				admissionResponse.Result = getInvalidContainerResponse(message)
				goto done
			}
			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					klog.Fatalf("Error while looking for image registry: %+v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !validRegistry {
					message := fmt.Sprintf("Container Image from a non whitelisted Registry" + container.Image)
					SendSlackNotification(message)
					admissionResponse.Result = getInvalidContainerResponse(message)
					goto done
				}
			}
		}
	} else {
		klog.Fatalf("Namespace is %s Whitelisted", namespace)
	}
done:
	ar = v1beta1.AdmissionReview{
		Response: &admissionResponse,
	}

	data, err = json.Marshal(ar)
	if err != nil {
		klog.Fatalln(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func SendSlackNotification(msg string) {
	if webhookUrl != "" {
		slackBody, _ := json.Marshal(SlackRequestBody{Text: msg})
		req, err := http.NewRequest(http.MethodPost, webhookUrl, bytes.NewBuffer(slackBody))
		if err != nil {
			klog.Fatalln(err)
		}

		req.Header.Add("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			klog.Fatalln(err)
		}

		buf := new(bytes.Buffer)
		_,_ = buf.ReadFrom(resp.Body)
		if buf.String() != "ok" {
			klog.Fatalln("Non-ok response return from Slack")
		}
		defer resp.Body.Close()
	} else {
		klog.Fatalln("Slack Webhook URL is not provided")
	}
}

func getInvalidContainerResponse(message string) *metav1.Status {
	return &metav1.Status{
		Reason: metav1.StatusReasonInvalid,
		Details: &metav1.StatusDetails{
			Causes: []metav1.StatusCause{
				{Message: message},
			},
		},
	}
}

func configTLS(config Config) *tls.Config {
	sCert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		klog.Fatalf("config=%#v Error: %v", config, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
}

func main() {
	var config Config
	flag.StringVar(&config.CertFile, "tls-cert", "/etc/admission-controller/tls/cert.pem", "TLS Certificate File.")
	flag.StringVar(&config.KeyFile, "tls-key", "/etc/admission-controller/tls/key.pem", "TLS Key File.")
	flag.Parse()
	klog.InitFlags(nil)

	http.HandleFunc("/ping", healthCheck)
	http.HandleFunc("/validate", validateAdmissionReviewHandler)
	s := &http.Server{
		Addr: ":443",
		TLSConfig: configTLS(config),
	}
	klog.Info(fmt.Sprintf("About to start serving webhooks: %#v", s))
	if err := s.ListenAndServeTLS("",""); err != nil {
		klog.Errorf("Failed to listen and server webhook server:%v", err)
	}

}
