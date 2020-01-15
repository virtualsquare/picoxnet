CFLAGS:=-I. -I/usr/include/picotcp -I/usr/local/include/picotcp -DUSENETLINK -fPIC -g -ggdb3

all: mytcp bestnetapitest vunetpicox.so iplinkadd

mytcp: mytcp.o pico_bsd_sockets.o picox_bsd.o picox_netlink.o picox_nl_ops.o
	gcc -o $@ $^ -pthread -lpicotcp -lvdeplug -lvpoll -lfduserdata -lnlq

bestnetapitest: bestnetapitest.o pico_bsd_sockets.o picox_bsd.o picox_netlink.o picox_nl_ops.o
	gcc -o $@ $^ -pthread -lpicotcp -lvdeplug -lvpoll -lfduserdata -lnlq

vunetpicox.so: vunetpicox.o pico_bsd_sockets.o picox_bsd.o picox_netlink.o picox_nl_ops.o
	gcc -o $@ $^ -shared -pthread -lpicotcp -lvdeplug -lvpoll -lfduserdata -lnlq

iplinkadd: iplinkadd.o

build-dep: /usr/lib/x86_64-linux-gnu/libvpoll.so /usr/lib/libpicotcp.so /usr/lib/x86_64-linux-gnu/libnlq.so /usr/bin/umvu
	
clean:
	@rm -rf *.o mytcp bestnetapitest vunetpicox.so

.PHONY: clean
	
/usr/lib/x86_64-linux-gnu/libvpoll.so: /usr/lib/libfduserdata.so
	git clone https://github.com/rd235/libvpoll-eventfd.git
	cd libvpoll-eventfd && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/x86_64-linux-gnu/libnlq.so:
	git clone https://github.com/virtualsquare/libnlq.git
	cd libnlq && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/bin/umvu: /usr/lib/x86_64-linux-gnu/libstropt.so /usr/include/strcase.h /usr/lib/x86_64-linux-gnu/libvolatilestream.so /usr/lib/x86_64-linux-gnu/libvdestack.so
	git clone https://github.com/virtualsquare/vuos.git
	cd vuos && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/x86_64-linux-gnu/libstropt.so:
	git clone https://github.com/rd235/libstropt.git
	cd libstropt && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/x86_64-linux-gnu/libvolatilestream.so:
	git clone https://github.com/rd235/libvolatilestream.git
	cd libvolatilestream && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/x86_64-linux-gnu/libvdestack.so:
	git clone https://github.com/rd235/libvdestack.git
	cd libvdestack && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/include/strcase.h:
	git clone https://github.com/rd235/strcase.git
	cd strcase && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/libfduserdata.so:
	git clone https://github.com/rd235/libfduserdata.git
	cd libfduserdata && cmake -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install && cd ..

/usr/lib/libpicotcp.so:
	git clone https://gitlab.com/insane-adding-machines/picotcp.git
	cd picotcp && make gnulib && sudo make gnulib-install

