CC ?= gcc

src_list := main_linux.c easy_setup_linux.c ping.c network_state.c  easy_setup/easy_setup.c easy_setup/scan.c proto/akiss.c proto/changhong.c proto/jingdong.c proto/neeze.c proto/ap.c proto/jd.c proto/mcast.c proto/xiaoyi.c
obj_list := $(src_list:%.c=%.o)

CFLAGS := -Ieasy_setup -Iproto
LIBS = -lpthread
.PHONY: setup

setup:$(obj_list)
	$(CC) -o $@ $^ $(LIBS)
	
%.o:%.c
	$(CC) -c $(CFLAGS) -o $@ $^

clean:
	rm $(obj_list) setup


