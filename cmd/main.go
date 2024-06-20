/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	secretsv1alpha1 "github.com/opensecrecy/encrypted-secrets/api/v1alpha1"
	"github.com/opensecrecy/encrypted-secrets/pkg/providers"
	//+kubebuilder:scaffold:imports
)

var (
	kubeconfig          string
	encryptedSecretName string
	namespace           string
	secretsDir          string
)

func init() {

	flag.StringVar(&encryptedSecretName, "encryptedsecret", "", "name of the EncryptedSecret object")
	flag.StringVar(&namespace, "namespace", "default", "namespace of the EncryptedSecret object")
	flag.StringVar(&secretsDir, "secrets-dir", "/opt/secrets/", "directory to store decrypted secrets")
	flag.Parse()

	secretsv1alpha1.AddToScheme(scheme.Scheme)

	//+kubebuilder:scaffold:scheme
}

func main() {

	var config *rest.Config
	var err error

	home := homedir.HomeDir()
	kubeconfig = filepath.Join(home, ".kube", "config")

	// check if the kubeconfig exists
	if _, err := os.Stat(kubeconfig); err != nil {
		log.Printf("using in-cluster configuration")
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err)
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}

	}

	secretsv1alpha1.AddToScheme(scheme.Scheme)
	// Define the namespace and name of the custom object
	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &schema.GroupVersion{
		Group:   secretsv1alpha1.GroupVersion.Group,
		Version: secretsv1alpha1.GroupVersion.Version,
	}
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = serializer.NewCodecFactory(scheme.Scheme)
	crdConfig.UserAgent = rest.DefaultKubernetesUserAgent()
	restClient, err := rest.UnversionedRESTClientFor(&crdConfig)
	if err != nil {
		panic(err)
	}

	encryptedSecret := secretsv1alpha1.EncryptedSecret{}

	err = restClient.Get().Resource("encryptedsecrets").Namespace(namespace).Name(encryptedSecretName).Do(context.Background()).Into(&encryptedSecret)
	if err != nil {
		panic(err)
	}

	decryptedObj, err := providers.DecodeAndDecrypt(&encryptedSecret)
	if err != nil {
		fmt.Printf("failed to decrypt value for %s", err.Error())
	}

	err = os.MkdirAll(secretsDir, 0755)
	if err != nil {
		fmt.Printf("failed to create directory %s", err.Error())
	}

	log.Println("writing decrypted secret to file")
	for key, value := range decryptedObj.Data {
		err = os.WriteFile(secretsDir+key, []byte(value), 0644)
		if err != nil {
			fmt.Printf("failed to write file %s", err.Error())
		}
	}

}
