all:
	@$(foreach BOF, $(wildcard ./*/SOURCE), make -C $(BOF) -f Makefile;)
clean:
	@$(foreach BOF, $(wildcard ./*/SOURCE), make -C $(BOF) -f Makefile clean;)
