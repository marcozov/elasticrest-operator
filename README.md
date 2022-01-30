# ElasticREST Operator
An operator for Elasticsearch REST API.

# How-to
operator-sdk init --domain elasticrest.io
operator-sdk create api --group elasticsearch --version v1alpha1 --kind ILMPolicy --resource --controller
operator-sdk create api --group elasticsearch --version v1alpha1 --kind IndexTemplate --resource --controller
