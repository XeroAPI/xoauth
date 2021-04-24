# Windows 64 bit
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o build/windows/xoauth.exe

# Mac OS x86 64 bit
env GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o build/darwin/xoauth

# Mac OS arm64
env GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o build/darwin/xoauth

# Linux 64 bit
env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/linux/xoauth

chmod +x build/linux/xoauth
chmod +x build/darwin/xoauth
chmod +x build/windows/xoauth.exe
