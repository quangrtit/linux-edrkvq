#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>

static int major;

static ssize_t my_read(struct file* f, char __user *u, size_t l, loff_t *o) {
    printk("hello_cdev - Read is called\n");
    return 0;
}

static struct file_operations fops = {
    .read = my_read
};

static int __init hello_init(void)
{
    // printk(KERN_INFO "[KHONG VAN QUANG] Hello, World!\n");
    major = register_chrdev(0, "hello_cdev", &fops);
    if(major < 0) {
        printk("hello_cdev - Error registering chrdev\n");
    }
    printk("hello_cdev - Major Device Number: %d\n", major);
    return 0;
}

static void __exit hello_exit(void)
{
    // printk(KERN_INFO "[KHONG VAN QUANG] Goodbye, World!\n");
    unregister_chrdev(major, "hello_cdev");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KHONG VAN QUAN");
MODULE_DESCRIPTION("A simple Hello World Linux kernel module");
