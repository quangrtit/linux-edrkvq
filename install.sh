#!/bin/bash
# # file thử
# f=main_test_block_exe

# # show initial times (human + epoch)
# echo "=== BEFORE ==="
# stat -c "mtime: %y\nmtime_epoch: %Y\nctime: %z\nctime_epoch: %Z\nsize: %s\n" "$f"

# # thay đổi chỉ metadata: chmod (ví dụ thêm quyền group write)
# chmod g+w "$f"

# # show after
# echo "=== AFTER chmod g+w ==="
# stat -c "mtime: %y\nmtime_epoch: %Y\nctime: %z\nctime_epoch: %Z\nsize: %s\n" "$f"

f=main_test_block_exe

# lưu mtime gốc (epoch seconds)
orig_mtime=$(stat -c %Y "$f")
echo "orig_mtime_epoch=$orig_mtime"

# show before
echo "=== BEFORE ==="
stat -c "mtime: %y\nmtime_epoch: %Y\nctime: %z\nctime_epoch: %Z\nsize: %s\n" "$f"

# 1) Thay đổi nội dung (ví dụ overwrite 10 bytes ở offset 100)
# dùng dd để viết 10 byte không thay đổi kích thước file (notrunc)
printf 'AAAAAAAAAA' | dd of="$f" bs=1 seek=100 conv=notrunc status=none

# show immediately after write
echo "=== AFTER content-write ==="
stat -c "mtime: %y\nmtime_epoch: %Y\nctime: %z\nctime_epoch: %Z\nsize: %s\n" "$f"

# 2) Giả sử attacker cố che dấu: restore mtime về giá trị ban đầu
# touch với epoch seconds: touch -d "@$orig_mtime" file
touch -d "@$orig_mtime" "$f"

# show after restoring mtime
echo "=== AFTER restoring mtime (touch) ==="
stat -c "mtime: %y\nmtime_epoch: %Y\nctime: %z\nctime_epoch: %Z\nsize: %s\n" "$f"