MacOS
=====

References:
-----------

* Code Signing:
    * https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html
    * https://developer.apple.com/library/archive/technotes/tn2206/_index.html

* Notarizing
    * https://developer.apple.com/documentation/xcode/notarizing_macos_software_before_distribution

Prereq:
-------

    sudo gem install asciidoctor
    pip3 install dmgbuild
    brew install pkgconfig sparkle doxygen libp11 libgnutils gettext asciidoctor docbook docbook-xsl
    brew install --cask libndi

Build:
------

Run one time only, or if moving to a new Wireshark revision

    tools/macos-setup.sh --install-optional

Here are some exports - CODE_SIGN_IDENTITY as per 'security find-identity -p codesigning -v login.keychain'

    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/Users/<identity>/Qt5.12.4/5.12.4/clang_64/lib/pkgconfig
    export CMAKE_PREFIX_PATH=/Users/<identity>/Qt5.12.4/5.12.4/clang_64/lib/cmake
    export CODE_SIGN_IDENTITY="AppNeta Inc"
    PATH=/Users/<identity>/Qt5.12.4/5.12.4/clang_64/bin:/Library/Frameworks/Python.framework/Versions/3.7/bin/:$PATH
    export PATH

    mkdir build; cd build
    cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -G Ninja ..
    ninja
    ninja app_bundle

Notarize:
---------

At this point you may want to notarize the app_bundle - you will require an
application-specific password - https://support.apple.com/en-us/HT204397

    cd run
    ditto -ck --keepParent Wireshark.app Wireshark.zip
    xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.app" --username <apple id> --password <app-specific password> --file Wireshark.zip

Wait up to 5 minutes for success - check using this command

    xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>

Staple the notarization result so app can be verified as notarized when offline

    xcrun stapler staple Wireshark.app
    cd ..

macOS Package:
--------------

    cd run
    ../packaging/macosx/osx-dmg.sh
    xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.dmg" --username <apple id> --password <app-specific password> --file Wireshark\ <version>\ Intel\ 64.dmg
    xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>
    xcrun stapler staple Wireshark\ <version>\ Intel\ 64.dmg
    cd ..

Linux
=====

To build Linux debug:
---------------------

    mkdir -p build-debug
    cd build-debug
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    make -j6

Make Linux Package:
------------------

Update version in CMakeList.txt and debian/changelog

    $ mkdir -p /tmp/wireshark_3.4.2.appneta.50_repo
    pdebuild --use-pdebuild-internal --debbuildopts "-b -a amd64 -us -uc" --buildresult /tmp/wireshark_3.4.2.appneta.50_repo

Once packages are made, do something like:

    $ cd /tmp/wireshark_3.4.2.appneta.50_repo
    $ dpkg-scanpackages . | xz -c > Packages.xz

Optionally you can move directory and install packages locally
... in /etc/apt/sources.list.d/wireshark.list ...

    deb [trusted=yes] file:/home/fklassen/data/wireshark_3.4.2.appneta.50_repo ./
    $ sudo apt update
    $ sudo apt install wireshark

Windows
=======

* Set up as per [install guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html).
  No need to install Git, CMake, Python or Perl on Windows Dev machine. Install Qt5 not Qt6.
  
* I had to open a regular Command Prompt and run 
  `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"`
  rather than open a "x64 Native Tools Command Prompt for VS 2019".

* Set the following environmental variables e.g.

    > set WIRESHARK_BASE_DIR=C:\Users\fklassen\git
    > set WIRESHARK_VERSION_EXTRA=-appneta.52
    > set QT5_BASE_DIR=C:\Qt\5.15.2\msvc2019_64\

* Create a build directory and change into it e.g

    > mkdir ..\wsbuild64
    > cd ..\wsbuild64

* Generate build files

     > "C:\Program Files\CMake\bin\cmake" -G "Visual Studio 16 2019" -A x64 ..\wireshark

* Make

    > msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln


