# ElasticREST Operator
An operator for Elasticsearch REST API.

The goal of this operator is to manage Elasticsearch resources in a declarative way.

The resources define via this operator take care of the entire lifeycle of the resources that are created on the target Elasticsearch backends, including the creation, update and deletion of such components.
Unlike other approaches (e.g., scripts that deploy the desired resources on an Elasticsearch cluster), this operator doesn't require that user performs manual cleanups when resourcees have to be deleted.

# Getting started
## Install with Helm
WIP

## Deploy Elasticsearch resources
Make sure that there is an Elasticsearch cluster deployed within your Kubernetes cluster.

At the moment, Elasticsearch clusters deployed without ECK and/or outside of the Kubernetes cluster where the operator runs are not supported.
### Add an ILM Policy
This wrapper provides the ILM creation/deletion functionalities: https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management-api.html#ilm-api-policy-endpoint .

Add the policy:
```
apiVersion: elasticsearch.elasticrest.io/v1alpha1
kind: ILMPolicy
metadata:
  name: ilmpolicy-sample
  namespace: elasticsearch
spec:
  elasticsearchCluster: quickstart
  body: |
    {
      "policy": {
        "_meta": {
          "description": "random description",
          "project": {
            "name": "myProject",
            "department": "myDepartment"
          }
        },
        "phases": {
          "warm": {
            "min_age": "9d",
            "actions": {
              "forcemerge": {
                "max_num_segments": 1
              }
            }
          },
          "delete": {
            "min_age": "24d",
            "actions": {
              "delete": {}
            }
          }
        }
      }
    }
```

# Supported Elasticsearch resources
The goal is to add as manny resource types as needed.

For now the following is available:
 - ILM Policy

# Useful readings
 - Getting started with operator-sdk: https://sdk.operatorframework.io/docs/building-operators/golang/tutorial/
 - Kubebuilder concepts: https://book.kubebuilder.io/introduction.html
