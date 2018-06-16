CFLAGS = -I../cjson

all:../cjson/cJSON.o test_cjson.o
	gcc -o json $^ -lm

clean:
	rm -f json *.o


