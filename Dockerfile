FROM swift:5.10-jammy
WORKDIR /app
COPY Package.swift ./
COPY Sources/ Sources/
COPY Tests/ Tests/
CMD ["swift", "test"]
