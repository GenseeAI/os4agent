#! /bin/bash

# copied and modified from hermit
# https://github.com/uclasystem/hermit/blob/master/linux-5.14-rc5/build_kernel.sh

### Parameters
version="7.0.1"

# Append a suffix
LocalVersion="-pgcachecow"
num_cores=$(($(nproc --all) - 2))
num_cores=$(( num_cores > 1 ? num_cores : 1 ))

## Functions
delete_old_kernel_contents () {
	if [[ $OS_DISTRO == "CentOS Linux" ]]
	then
		echo "sudo rm /boot/initramfs-${version}${LocalVersion}.img   /boot/System.map-${version}${LocalVersion}  /boot/vmlinuz-${version}${LocalVersion} "
		sleep 1
		sudo rm /boot/initramfs-${version}${LocalVersion}.img   /boot/System.map-${version}${LocalVersion}  /boot/vmlinuz-${version}${LocalVersion}
	elif [ $OS_DISTRO == "Ubuntu" ]
	then
		echo "sudo rm /boot/initrd.img-${version}${LocalVersion} /boot/System.map-${version}${LocalVersion} /boot/vmlinuz-${version}${LocalVersion} /boot/config-${version}${LocalVersion}"
		sleep 1
		sudo rm /boot/initrd.img-${version}${LocalVersion} /boot/System.map-${version}${LocalVersion} /boot/vmlinuz-${version}${LocalVersion} /boot/config-${version}${LocalVersion}
	fi
}

install_new_kernel_contents () {
	echo "install kernel modules"
	sleep 1
	sudo make -j${num_cores} INSTALL_MOD_STRIP=1 modules_install

	echo "install kernel image"
	sleep 1
	sudo make install
}

update_grub_entries () {
	# The kernel boot version
	grub_boot_verion=4

	if [[ $OS_DISTRO == "CentOS Linux" ]]
	then
		# For CentOS, there maybe 2 grub entries
		echo "(MUST run with sudo)Delete old grub entry:"

		efi_grub="/boot/efi/EFI/centos/grub.cfg"
		if [[ -e /boot/efi/EFI/centos/grub.cfg ]]
		then
			echo " Delete EFI grub : sudo rm ${efi_grub}"
			sleep 1
			sudo rm ${efi_grub}

			echo " Rebuild EFI grub : sudo grub-mkconfig -o ${efi_grub}"
			sleep 1
			sudo grub2-mkconfig -o ${efi_grub}

		else
			echo "Delete /boot/grub/grub.cfg"
			sleep 1
			sudo rm /boot/grub/grub.cfg

			echo "Rebuild the grub.cfg"
			echo "grub-mkconfig -o /boot/grub/grub.cfg"
			sleep 1
			sudo grub2-mkconfig -o /boot/grub/grub.cfg
		fi

		echo "Set bootable kernel verion to ${version}"
		echo "Set default entry to Item ${grub_boot_verion} (Please check if this is the expected ${version})"
		sudo grub-set-default ${grub_boot_verion}

		echo "Current grub entry"
		sleep 1
		sudo grub-editenv list

	elif [ $OS_DISTRO == "Ubuntu" ]
	then
		new_default="GRUB_DEFAULT=\"Advanced options for Ubuntu>Ubuntu, with Linux ${version}${LocalVersion}\""
		grub_file="/etc/default/grub"

		if grep -Fxq "$new_default" "$grub_file"
		then
			echo "The default kernel version is already set to ${version}${LocalVersion}"
		else
			echo "move the old grub config from ${grub_file} to ${grub_file}.old"
			sudo cp $grub_file "${grub_file}.old"

			echo "Set the default kernel version to ${version}${LocalVersion}"
			sed -e "/^GRUB_DEFAULT/a${new_default}" -e 's/^GRUB_DEFAULT/# GRUB_DEFAULT/' < $grub_file | sudo tee $grub_file > /dev/null

			echo "update-grub"
			sudo update-grub
		fi
	fi
}

### Operations
op=$1
if [ -z "${op}"  ]
then
	echo "Please select the operation, e.g. build, install, replace, headers-install, update-grub"
	read op
fi
echo "Do the action ${op}"

### Detect Linux releases
OS_DISTRO=$( awk -F= '/^NAME/{print $2}' /etc/os-release | sed -e 's/^"//' -e 's/"$//' )
if [[ $OS_DISTRO == "CentOS Linux" ]]
then
	echo "Running on CentOS..."
elif [ $OS_DISTRO == "Ubuntu" ]
then
	echo "Running on Ubuntu..."
fi

### Do the action
if [ "${op}" = "build" ]
then
	echo "make oldconfig"
	sleep 1
	make oldconfig

	echo "make -j${num_cores} LOCALVERSION=${LocalVersion} > >(tee build.log) 2> >(tee build_error.log >&2)"
	sleep 1
	make -j${num_cores} LOCALVERSION=${LocalVersion} > >(tee build.log) 2> >(tee build_error.log >&2)

elif [ "${op}" = "install" ]
then
	delete_old_kernel_contents
	sleep 1
	install_new_kernel_contents
	sleep 1

	update_grub_entries

elif [ "${op}" = "replace"  ]
then
	echo "Install kernel image only"
	delete_old_kernel_contents
	sleep 1
	sudo make install
	sleep 1

	update_grub_entries

elif [ "${op}" = "headers-install" ]
then
	echo "Warning - the kernel headers install may overwirite"
	echo "the original headers installed by other libraries !!"
	echo "Must backup the headers first !!"
	header_path="/usr/src/linux-headers-${version}${LocalVersion}"
	echo "Install uapi kernel headers to $header_path"
	echo "STOP the installation if you didn't back up the /usr/include !!"
	echo "3"
	sleep 3

	echo "2"
	sleep 3

	echo "1"
	sleep 3
	sudo mkdir -p $header_path
	sudo make headers_install INSTALL_HDR_PATH=$header_path

elif [ "${op}" = "update-grub"  ]
then
	update_grub_entries

else
	echo "!! Wrong Operation - ${op} !!"
fi
