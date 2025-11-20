# Release

This document describes a release procedure for sanctum.

Cutting a release boils down to the following steps:

* checkout releng
* merge master into releng
* update RELEASE file and commit
* tag new release
* archive release
* upload release

## Cutting release

```
$ git checkout releng
$ git merge master
$ echo "X.Y.Z" > RELEASE
$ git commit -m "X.Y.Z" RELEASE
$ git tag -a X.Y.Z
$ git archive --format=tgz --prefix=sanctum-X.Y.Z/ -o ~/sanctum-X.Y.Z.tgz X.Y.Z
$ git push origin --tags releng
$ git push github --tags releng
```

## Signing release

Not yet in place.

## Uploading release

```
$ scp ~/sanctum-X.Y.Z.tgz release.host:/var/chroot/sanctorum/webroot/releases
```

## Updating www

Edit relevant HTML files under **www** and commit.
Deploy them onto the release.host.
