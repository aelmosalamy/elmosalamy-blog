---
title: Linux into the scene!
author: aelmosalamy
date: 2018-11-30
author: aelmosalamy
tags: [linux, ubuntu, foss]
---

Hello everyone,

Recently, while watching a video, I came across a guy using Linux on his machine, It looked really clean and neat and I wanted to try it!

At the start it just looked cool and I thought why not download it? It is free and open-source. I looked up for Linux and found it have what is known as "distros".

Basically distros or distributions are a different variations of Linux, with every distro having its own look and settings - think of it as ice cream flavours - It can be different File manager or different interface, terminal and so on. I searched for the most popular distros - I wanted something solid with a big community - and I came across Ubuntu, a quick glance at its interface and I loved it instantly!

{{<figure src="/images/ubuntu-logo.png" title="Ubuntu Logo">}}

So I went to the Ubuntu website and downloaded the latest LTS release, then...

I didn't know how to install it, I never installed an operating system myself. After some research, I realized I have to dual-boot - Installing two systems and become able to choose between them - Windows with Ubuntu, I wasn't sure how to do that, I saw many videos and tutorials and it looked easy; however, I was kinda scared. scared I might mess something up and I end up with a corrupt disk, computer doesn't boot properly, or anything you can imagine when you think of playing around with operating systems.

Anyway, I decided to try and do it anyway, It changed from being just a personal preference to a must-do-this challenge. Now that I've done it, I can tell you it was pretty easy and straightforward, and it unlikely - If you follow the instructions - to mess anything up.

**Here is what I did to dual-boot Ubuntu with my Windows:**

1. Download the ISO file for Ubuntu's long-term-support release from their website.
2. Use Windows' Disk Management utility to partition my hard drive, I made a 800 GBs partition for my files and another 200 GBs empty partition for Ubuntu.
3. Insert a USB Flash drive (The data on it will be deleted so make sure you don't need them) and format it, make sure to use FAT32 filesystem.
4. Download [Rufus](https://rufus.ie/en_IE.html)  and open it, give it your downloaded ISO file, specify your USB location and press "Start", it will take 3-5 mins to create your Bootable USB, close Rufus when done.
5. Open the "Change advanced startup options" on your Windows - on Windows 10, you can find it by searching "boot" - then click on "Restart" under "Advanced startup options" and select "Boot from USB . . ." option.
6. After few seconds a black loading screen saying "Ubuntu" will appear and prompt you "Try Ubuntu" or "Install Ubuntu", I recommend trying it so you can decide whether you like it - which is very likely - or you gonna think about it.
7. If you are going to "Install Ubuntu" then you will run through a straightforward wizard setting up your partitions, setting your computer name, users, location and time, etc...
8. Now you can use your new OS, every time you power up your computer a Boot Loader program called GRUB will give you choices you can then select either Ubuntu or Windows.
9. Enjoy!

Note: You can access your Windows file from Ubuntu and not vice versa, Ubuntu supports the NTFS filesystem (The one Window's use) while Windows need some special software so it can read the exFAT filesystem Ubuntu use (Another try by Microsoft to stay dominating I guess).

{{<figure src="/images/ubuntu-desktop.png" caption="Ubuntu's desktop">}}

**Customizing Ubuntu:**

Ubuntu and Linux generally are known for their versatility, theoretically you can customize everything in Linux, ranging as high as the graphical interface and as deep as your system's kernel. There is plenty of beautiful themes available for download, one of my favorite themes is the *X Arc Dark* which is part of the *X Arc Collection,* you can download it [here](https://www.gnome-look.org/p/1167049/).

You need to download the GNOME Tweaks tool which is found at Ubuntu's Software Center, using this you will be able to change themes (You gotta search for yourself how to apply the *X Arc* themes though, additionally this tool gives you many options to "tweak" and customize your system, surely it is a must-have.

**Software:**

Ubuntu comes with a preinstalled office alternatives, LibreOffice, which is nothing fancy, it has all the necessary features you would expect from Word, Excel and Powerpoint.

I downloaded the following free software:

- Pinta instead of MS Paint
- GIMP instead of Photoshop
- Inkscape instead of Illustrator
- Visual Studio Code
- Blender3D
- VLC Media Player (is a must)
- Kazam screen-recorder (I was planning to record some tuts)

This is the basic, yet great FOSS bundle.

**Conclusion:**

I loved Ubuntu, it got that great look and feeling, it is solid and stable and you can customize everything to your liking, it was a great experience, I learned a lot just from the installation process.

I was able to test ASCII Combat on UNIX systems (And fixed one little bug too) also I planning to get into is: Shell-scripting which is amazing if you want to get your hands dirty with servers, who knows maybe I can become a sysadmin? (Nah, just kidding :P).
