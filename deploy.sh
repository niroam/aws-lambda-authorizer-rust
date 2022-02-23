#!/bin/bash
# Deploy Infraa

pushd .
cd ./infra/terraform/
terraform apply --auto-approve
popd
