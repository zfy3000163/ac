main:detection_common_bnfasearch.o detection_common_mpse.o detection_common_mem.o main.o detection_common_acsmx.o detection_common_acsmx2.o\
		detection_common_ksearch.o

	gcc  -o $@ $^ 
%.o:%.c
	gcc -g -c $< -I./include

clean:
	rm -rf *.o main
