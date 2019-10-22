/*

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

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	owaspzapv1alpha1 "github.com/zee-ahmed/kube-owasp-zap-operator/api/v1alpha1"
)

// ScansReconciler reconciles a Scans object
type ScansReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=owaspzap.simplyzee.dev,resources=scans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=owaspzap.simplyzee.dev,resources=scans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=owaspzap.simplyzee.dev,resources=scans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *ScansReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("scans", req.NamespacedName)

	scans := owaspzapv1alpha1.Scans{}
	if err := r.Client.Get(ctx, req.NamespacedName, &scans); err != nil {
		log.Error(err, "Failed to get Scans resource")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.cleanupOwnedResources(ctx, log, &scans); err != nil {
		log.Error(err, "failed to clean up old Pod resources for this Scans")
		return ctrl.Result{}, err
	}

	log = log.WithValues("Name", scans.Name)

	log.Info("checking if an existing Pod exists for this resource")
	pod := core.Pod{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: scans.Namespace, Name: scans.Name}, &pod)
	if apierrors.IsNotFound(err) {
		log.Info("could not find existing Pod for Scans, creating one...")

		pod = *buildPod(scans)
		if err := r.Client.Create(ctx, &pod); err != nil {
			log.Error(err, "failed to create Pod resource")
			return ctrl.Result{}, err
		}

		r.Recorder.Eventf(&scans, core.EventTypeNormal, "Created", "Created pod %q", pod.Name)
		log.Info("created Pod resource for Scans")
		return ctrl.Result{}, nil
	}
	if err != nil {
		log.Error(err, "failed to get Pod for Scans resource")
		return ctrl.Result{}, err
	}

	log.Info("existing Pod resource already exists for Scans")

	return ctrl.Result{}, nil
}

// cleanupOwnedResources will Delete any existing Deployment resources that
// were created for the given Scans that no longer match the
// scan.Name field.
func (r *ScansReconciler) cleanupOwnedResources(ctx context.Context, log logr.Logger, scan *owaspzapv1alpha1.Scans) error {
	log.Info("finding existing pods for Scans resource")

	var pods core.PodList
	if err := r.List(ctx, &pods, client.InNamespace(scan.Namespace), client.MatchingField(podOwnerKey, scan.Name)); err != nil {
		return err
	}

	deleted := 0
	for _, pod := range pods.Items {
		if pod.Name == scan.Name {
			// If this deployment's name matches the one on the Scans resource
			// then do not delete it.
			continue
		}

		if err := r.Client.Delete(ctx, &pod); err != nil {
			log.Error(err, "failed to delete Pod resource")
			return err
		}

		r.Recorder.Eventf(scan, core.EventTypeNormal, "Deleted", "Deleted pod %q", pod.Name)
		deleted++
	}

	log.Info("finished cleaning up old Pod resources", "number_deleted", deleted)

	return nil
}

func buildPod(scans owaspzapv1alpha1.Scans) *core.Pod {
	var debug, spider, recursiveScan string

	if scans.Spec.Debug {
		debug = "--verbose"
	}

	if scans.Spec.Spider {
		spider = "--spider"
	}

	if scans.Spec.RecursiveScans {
		recursiveScan = "-r"
	}

	pod := core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            scans.Name,
			Namespace:       scans.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&scans, owaspzapv1alpha1.GroupVersion.WithKind("Scans"))},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{
				{
					Name:  "scan",
					Image: "owasp/zap2docker-stable:latest",
					Command: []string{
						"zap-cli",
						debug,
						"quick-scan",
						"--self-contained",
						"--start-options",
						"-config api.disablekey=true",
						"-s xss,sqli",
						spider,
						recursiveScan,
						scans.Spec.TargetURL,
					},
					Resources: core.ResourceRequirements{
						Requests: map[core.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("300Mi"),
						},
						Limits: map[core.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("500Mi"),
						},
					},
				},
			},
		},
	}

	return &pod
}

var (
	podOwnerKey = ".metadata.controller"
)

func (r *ScansReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(&core.Pod{}, podOwnerKey, func(rawObj runtime.Object) []string {
		// grab the Pod object, extract the owner...
		pod := rawObj.(*core.Pod)
		owner := metav1.GetControllerOf(pod)
		if owner == nil {
			return nil
		}
		// ...make sure it's a Scans...
		if owner.APIVersion != owaspzapv1alpha1.GroupVersion.String() || owner.Kind != "Scans" {
			return nil
		}

		// ...and if so, return it
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&owaspzapv1alpha1.Scans{}).
		Owns(&core.Pod{}).
		Complete(r)
}
