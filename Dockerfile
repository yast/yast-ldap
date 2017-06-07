FROM yastdevel/cpp:sle12-sp2
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  libldapcpp-devel
COPY . /usr/src/app
