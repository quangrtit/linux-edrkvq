# Define the module to be built
obj-m += my_driver.o

# Kernel source directory
KDIR := /lib/modules/$(shell uname -r)/build

# Build directory for output files
BUILD_DIR := $(CURDIR)/build

# Destination directory for installing the module
DEST_DIR := /lib/modules/$(shell uname -r)/kernel/drivers/misc

# Specify the compiler to match the kernel's compiler
CC := x86_64-linux-gnu-gcc-13

# Ensure the source file is explicitly included
SOURCES := my_driver.c

all:
	@echo "Building kernel module..."
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) modules
	@mkdir -p $(BUILD_DIR)
	@mv -f *.o .*.o *.ko .*.cmd *.mod *.mod.c Module.symvers modules.order $(BUILD_DIR) 2>/dev/null || true

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	@rm -rf $(BUILD_DIR)

install:
	@echo "Installing module..."
	@sudo cp $(BUILD_DIR)/my_driver.ko $(DEST_DIR)/
	@sudo depmod -a
	@sudo modprobe my_driver

uninstall:
	@echo "Uninstalling module..."
	@sudo modprobe -r my_driver
	@sudo rm -f $(DEST_DIR)/my_driver.ko
	@sudo depmod -a