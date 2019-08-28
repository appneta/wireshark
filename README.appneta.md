MacOS
=====

References
----------

* Code Signing:
  * <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>
  * <https://developer.apple.com/library/archive/technotes/tn2206/_index.html>

* Notarizing
  * <https://developer.apple.com/documentation/xcode/notarizing_macos_software_before_distribution>

Prerequisites
-------------

```shell
 sudo gem install asciidoctor
 pip3 install dmgbuild
 brew install pkgconfig sparkle doxygen libp11 libgnutils gettext asciidoctor docbook docbook-xsl
 brew install --cask libndi
```

Build
-----

* Run one time only, or if moving to a new Wireshark revision

    ```shell
    tools/macos-setup-brew.sh --install-optional
    ```    

* Here are some exports

    ```shell
    export PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig
    export CMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@6
    export PATH=/usr/local/opt/qt@6/bin:$PATH
    ```

* Choose a code signing certificate
  * in this example I want to use certificate #4 which was most recently created in XCode Preferences

    ```shell
    ❯ security find-identity -p codesigning -v login.keychain
    1) 02BD99C3D9CE9E301DF3D9D2E1C6148DFE95AC79 "Apple Development: fred.klassen@broadcom.com (PZ339J2MU7)"
    2) AA173803B28511E3EE2D222D1054A63A7B1938DB "Apple Development: Fred Klassen (VRZWY3PKS3)"
    3) 0E3D74157F689870D378A291EBC3B1C927BA28D2 "Mac Developer: Fred Klassen (VRZWY3PKS3)"
    4) 8FE4FBC459A9DA4B372D15A8F606D9B976DE339B "Apple Development: Fred Klassen (VRZWY3PKS3)"
    4 valid identities found
    ```

  * for clarity I use `8FE4FBC459A9DA4B372D15A8F606D9B976DE339B`  but could also select `Apple Development: Fred Klassen (VRZWY3PKS3)`
* Build

    ```shell
    mkdir build; cd build
    cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -G Ninja ..
    cmake --build .
    ```

* Build an app bundle and sign it

    ```shell
    cmake --build . --target wireshark_app_bundle
    codesign --sign "8FE4FBC459A9DA4B372D15A8F606D9B976DE339B" --prefix "org.broadcom.appneta" \
    --entitlements ~/git/wireshark/packaging/macosx/entitlements.plist --timestamp --verbose --deep -f \
    run/Wireshark.app
    ```

* Test and note any error messages regarding missing libraries

    ```shell
    run/Wireshark.app/Contents/MacOS/Wireshark --help
    run/Wireshark.app/Contents/MacOS/Wireshark
    ```

  * often QtDBus.framework is missing so copy it (must use `ditto` not `cp -r`)

    ```shell
    pushd run/Wireshark.app/Contests/Frameworks
    ditto /opt/homebrew/Cellar/qt//6.6.0/lib/QtDBus.framework QtDBus.framework
    codesign --sign "8FE4FBC459A9DA4B372D15A8F606D9B976DE339B" --prefix "org.broadcom.appneta" --entitlements ~/git/wireshark/packaging/macosx/entitlements.plist --timestamp --verbose -f --deep QtDBus.framework
    popd
    ```

  * if libraries are missing, it may be easier to install upstream official build and copy those libraries as they have updated @rpath

    ```shell
    pushd run/Wireshark.app/Contests/Frameworks
    ditto /Applications/Wireshark_orig.app/Contents/Frameworks/libdbus.1.3.dylib .
    codesign --sign "8FE4FBC459A9DA4B372D15A8F606D9B976DE339B" --prefix "org.broadcom.appneta" --entitlements ~/git/wireshark/packaging/macosx/entitlements.plist --timestamp --verbose -f libdbus.1.3.dylib
    popd
    ```

* Make a backup copy of `run/Wireshark.app` as the next command will break it

    ```shell
    mkdir -p ~/data
    ditto run/Wireshark.app ~/data/
    ```

* Make the install `.dmg` file

    ```shell
    cmake --build . --target wireshark_dmg
    ```

* Replace a broken `Wireshark.app` in the dmg bundle with the working one

    ```shell
    pushd run
    hdiutil convert Wireshark\ 4.2.0.appneta.58\ Arm\ 64.dmg -format UDRW -o Wireshark\ 4.2.0.appneta.58\ Arm\ 64-rw.dmg
    hdiutil resize -size 500M Wireshark\ 4.2.0.appneta.58\ Arm\ 64-rw.dmg
    hdiutil attach Wireshark\ 4.2.0.appneta.58\ Arm\ 64-rw.dmg
    rm -rf /Volumes/Wireshark\ 4.2.0.appneta.58/Wireshark.app
    ditto ~/data/Wireshark.app /Volumes/Wireshark\ 4.2.0.appneta.58/Wireshark.app
    ```

  * At this point you will use Finder to unmount the `.dmg` bundle
  * Now convert R/W bundle to R/O

    ```shell
    hdiutil convert Wireshark\ 4.2.0.appneta.58\ Arm\ 64-rw.dmg -format UDRO -o ~/data/Wireshark\ 4.2.0.appneta.58\ Arm\ 64.dmg
    popd
    ```
* Code sign the new bundle

    ```shell
    codesign --sign "8FE4FBC459A9DA4B372D15A8F606D9B976DE339B" --prefix "org.broadcom.appneta" --entitlements ~/git/wireshark/packaging/macosx/entitlements.plist --timestamp --verbose -f Wireshark\ 4.2.0.appneta.58\ Arm\ 64.dmg
    ```

* Test the new installer program

Notarize - optional (only supported on TC build machines)
---------------------------------------------------------

At this point you may want to notarize the app_bundle - you will require an
application-specific password - <https://support.apple.com/en-us/HT204397>

```shell
cd run
ditto -ck --keepParent Wireshark.app Wireshark.zip
xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.app" --username <apple id> --password <app-specific password> --file Wireshark.zip
```

Wait up to 5 minutes for success - check using this command

```shell
xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>
```

Staple the notarization result so app can be verified as notarized when offline

```shell
xcrun stapler staple Wireshark.app
cd ..
```

macOS Notarize Package
----------------------

* this probably will break `Wireshark.app` but it is here for reference

```shell
cd run
../packaging/macosx/osx-dmg.sh
xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.dmg" --username <apple id> --password <app-specific password> --file Wireshark\ <version>\ Intel\ 64.dmg
xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>
xcrun stapler staple Wireshark\ <version>\ Intel\ 64.dmg
cd ..
```

Linux
=====

To build Linux debug
---------------------

```shell
mkdir -p build-debug
cd build-debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j6
```

Make Linux Package
------------------

Update version in CMakeList.txt and debian/changelog

    $ mkdir -p build-release && cd build-release
    $ cmake ..
    $ ln -s ../packaging/debian
    $ dpkg-buildpackage -S -d -us -uc
    $ mkdir -p /tmp/wireshark_4.4.1.appneta.59_repo
    $ mv ../wireshark_4.4.1* ~/data/wireshark-4.4.1-appneta.59_repo

Once packages are made, do something like:

    cd ~/data/wireshark-4.4.1-appneta.59_repo
    dpkg-scanpackages . | xz -c > Packages.xz

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
