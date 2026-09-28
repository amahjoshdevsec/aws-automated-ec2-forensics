.PHONY: init plan apply test investigate smoke destroy fmt

init:        ## terraform init
	cd terraform && terraform init
plan:        ## terraform plan
	cd terraform && terraform plan
apply:       ## deploy the stack
	cd terraform && terraform apply
test:        ## offline tests (no AWS credentials needed)
	python -m pytest -q tests/ && cd terraform && terraform test
investigate: ## start an investigation of the demo target
	bash scripts/start-investigation.sh
smoke:       ## end-to-end test with programmatic approval
	bash scripts/smoke-test.sh
destroy:     ## clean up workflow-created resources, then destroy
	bash scripts/pre-destroy.sh --delete-evidence && cd terraform && terraform destroy
fmt:
	cd terraform && terraform fmt -recursive
