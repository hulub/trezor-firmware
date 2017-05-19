all: messages.pb.c storage.pb.c types.pb.c

%.pb.c: %.pb %.options
	python ../../../nanopb-0.2.9.3-windows-x86/generator/nanopb_generator.py $< -L '#include "%s"' -T

%.pb: %.proto
	protoc -I/usr/include -I. $< -o $@

clean:
	rm -f *.pb *.o *.pb.c *.pb.h
