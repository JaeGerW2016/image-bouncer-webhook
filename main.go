package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"image-bouncer-webhook/rules"
	"image-bouncer-webhook/slack"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"net/http"
	"os"
	"strings"
)

var (
	whitelistNamespaces   = os.Getenv("WHITELIST_NAMESPACES")
	whitelistRegistries   = os.Getenv("WHITELIST_REGISTRIES")
	webhookUrl            = os.Getenv("WEBHOOK_URL")
	whitelistedNamespaces = strings.Split(whitelistNamespaces, ",")
	whitelistedRegistries = strings.Split(whitelistRegistries, ",")
)

type Config struct {
	CertFile string
	KeyFile  string
}

type admitFunc func(review v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

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

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func apply(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	klog.Info("Enetering apply in Image bouncer webhook")
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if ar.Request.Resource != podResource {
		klog.Errorf("expect resource to be %s", podResource)
		return nil
	}
	raw := ar.Request.Object.Raw
	pod := v1.Pod{}
	if err := json.Unmarshal(raw, &pod); err != nil {
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	namespace := ar.Request.Namespace
	klog.V(2).Infof("AdmissionReview Namespace: %s \n", namespace)
	images := make([]string, 2)
	initImage := make([]string, 2)

	if !rules.IsWhitelistNamespace(whitelistedNamespaces, namespace) {
		for _, container := range pod.Spec.InitContainers {
			initImage = append(initImage, container.Image)
			usingLatestTag, err := rules.IsUsingLatestTag(container.Image)
			if err != nil {
				klog.Errorf("Error while parsing initimage name: %+v ", err)
				return toAdmissionResponse(err)
			}
			if usingLatestTag {
				message := fmt.Sprintf("InitContainer Images using latest tag are not allowed " + container.Image)
				klog.Info(message)
				s := slack.NewSlackNotifier(webhookUrl)
				err := s.NotifyPodTermination(pod)
				if err != nil {
					klog.Error(err)
				}
				reviewResponse.Allowed = false
				reviewResponse.Result = getInvalidContainerResponse(message)
				break
			}
			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					klog.Errorf("Error while looking for image registry: %+v ", err)
					return toAdmissionResponse(err)
				}

				if !validRegistry {
					message := fmt.Sprintf("InitContainer Image from a non whitelisted Registry " + container.Image)
					klog.Info(message)
					s := slack.NewSlackNotifier(webhookUrl)
					err := s.NotifyPodTermination(pod)
					if err != nil {
						klog.Error(err)
					}
					reviewResponse.Allowed = false
					reviewResponse.Result = getInvalidContainerResponse(message)
					break
				}
			}
		}
		for _, container := range pod.Spec.Containers {
			images = append(images, container.Image)
			usingLatestTag, err := rules.IsUsingLatestTag(container.Image)
			if err != nil {
				klog.Errorf("Error while parsing image name: %+v", err)
				return toAdmissionResponse(err)
			}

			if usingLatestTag {
				message := fmt.Sprintf("Container Images using latest tag are not allowed " + container.Image)
				klog.Info(message)
				s := slack.NewSlackNotifier(webhookUrl)
				err := s.NotifyPodTermination(pod)
				if err != nil {
					klog.Error(err)
				}
				reviewResponse.Allowed = false
				reviewResponse.Result = getInvalidContainerResponse(message)
				break
			}

			if len(whitelistedRegistries) > 0 {
				validRegistry, err := rules.IsFromWhiteListedRegistry(container.Image, whitelistedRegistries)
				if err != nil {
					klog.Errorf("Error while looking for image registry: %+v", err)
					return toAdmissionResponse(err)
				}

				if !validRegistry {
					message := fmt.Sprintf("InitContainer Image from a non whitelisted Registry" + container.Image)
					klog.Info(message)
					s := slack.NewSlackNotifier(webhookUrl)
					err := s.NotifyPodTermination(pod)
					if err != nil {
						klog.Error(err)
					}
					reviewResponse.Allowed = false
					reviewResponse.Result = getInvalidContainerResponse(message)
					break
				}
			}
		}
	}
	if reviewResponse.Allowed {
		klog.Infof("All images accepted: %v %v", initImage, images)
	} else {
		klog.Infof("Rejected images: %v %v", initImage, images)
	}

	klog.Infof("admission response: %+v", reviewResponse)
	return &reviewResponse
}

func serve(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	var reviewRespone *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(body, &ar); err != nil {
		klog.Error(err)
		reviewRespone = toAdmissionResponse(err)
	} else {
		reviewRespone = admit(ar)
	}

	response := v1beta1.AdmissionReview{
		Response: reviewRespone,
	}

	resp, err := json.Marshal(response)
	if err != nil {
		klog.Error(err)
	}
	if _, err := w.Write(resp); err != nil {
		klog.Error(err)
	}
}

func serverIB(w http.ResponseWriter, r *http.Request) {
	serve(w, r, apply)
}

func main() {
	var config Config
	flag.StringVar(&config.CertFile, "tls-cert", "/etc/admission-controller/tls/cert.pem", "TLS Certificate File.")
	flag.StringVar(&config.KeyFile, "tls-key", "/etc/admission-controller/tls/key.pem", "TLS Key File.")
	flag.Parse()
	klog.InitFlags(nil)

	http.HandleFunc("/validate", serverIB)
	s := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(config),
	}
	klog.Info(fmt.Sprintf("About to start serving webhooks: %#v", s))
	if err := s.ListenAndServeTLS("", ""); err != nil {
		klog.Errorf("Failed to listen and server webhook server:%v", err)
	}

}
