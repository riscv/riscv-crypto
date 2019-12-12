
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

spec:
	$(MAKE) -C $(REPO_HOME)/doc/ spec

clean:
	$(MAKE) -C $(REPO_HOME)/doc/ clean

