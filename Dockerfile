FROM aa8y/sbt:1.0

RUN mkdir -p /app/project
WORKDIR /app

# Cache the SBT JARs in a layer.
COPY project/build.properties project/
RUN sbt update

# Cache the project-specific JARs.
COPY project/*.sbt ./project
COPY build.sbt .
COPY lock.sbt .
RUN sbt update

# Copy the rest of the files. dockerignore should skip the files we don't want.
COPY . ./
RUN sbt compile
RUN sbt test:compile
