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
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	tlsCertFile string
	tlsKeyFile  string
)

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
	log.Printf("Serving Request: %s", r.URL.Path)
	w.WriteHeader(http.StatusOK)
}

func validateAdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Serving Request: %s", r.URL.Path)
	// set header
	w.Header().Set("Content-Type", "application/json")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println(string(data))
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(data, &ar); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	namespace := ar.Request.Namespace
	log.Printf("AdmissionReview Namespace: %s", namespace)

	admissionResponse := v1beta1.AdmissionResponse{Allowed: true}
	images := make([]string,2)
	initImages := make([]string,2)


	if !rules.IsWhitelistNamespace(whitelistedNamespaces, namespace) {
		pod := v1.Pod{}
		if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Handle InitContainers
		for _, container := range pod.Spec.InitContainers {
			initImages = append(initImages, container.Image)
			usingLatest, err := rules.IsUsingLatestTag(container.Image)
			if err != nil {
				log.Printf("Error while parsing initimage name: %+v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if usingLatest {
				admissionResponse.Allowed = false
				message := fmt.Sprintf("InitContainer Images using latest tag are not allowed" + container.Image)
				SendSlackNotification(message)
				admissionResponse.Result = getInvalidContainerResponse(message)
				goto done
			}
			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					log.Printf("Error while looking for image registry: %+v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !validRegistry {
					admissionResponse.Allowed = false
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
				log.Printf("Error while parsing image name: %+v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if usingLatest {
				admissionResponse.Allowed = false
				message := fmt.Sprintf("Container Images using latest tag are not allowed" + container.Image)
				SendSlackNotification(message)
				admissionResponse.Result = getInvalidContainerResponse(message)
				goto done
			}
			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					log.Printf("Error while looking for image registry: %+v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !validRegistry {
					admissionResponse.Allowed = false
					message := fmt.Sprintf("Container Image from a non whitelisted Registry" + container.Image)
					SendSlackNotification(message)
					admissionResponse.Result = getInvalidContainerResponse(message)
					goto done
				}
			}
		}
	} else {
		log.Printf("Namespace is %s Whitelisted", namespace)
	}
done:
	ar = v1beta1.AdmissionReview{
		Response: &admissionResponse,
	}

	data, err = json.Marshal(ar)
	if err != nil {
		log.Println(err)
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
			log.Println(err)
		}

		req.Header.Add("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
		}

		buf := new(bytes.Buffer)
		_,_ = buf.ReadFrom(resp.Body)
		if buf.String() != "ok" {
			log.Println("Non-ok response return from Slack")
		}
		defer resp.Body.Close()
	} else {
		log.Println("Slack Webhook URL is not provided")
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

func main() {
	flag.StringVar(&tlsCertFile, "tls-cert", "/etc/admission-controller/tls/cert.pem", "TLS Certificate File.")
	flag.StringVar(&tlsKeyFile, "tls-key", "/etc/admission-controller/tls/key.pem", "TLS Key File.")
	flag.Parse()

	http.HandleFunc("/ping", healthCheck)
	http.HandleFunc("/validate", validateAdmissionReviewHandler)
	s := http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			ClientAuth: tls.NoClientCert,
		},
	}
	log.Fatal(s.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}
