# Use an official OpenJDK runtime as a parent image
FROM openjdk:11-jre-slim

# Set the working directory
WORKDIR /app

# Add the project JAR file to the container
COPY target/polls-0.0.1-SNAPSHOT.jar app.jar

# Timezone setting
RUN apt-get update && apt-get install -y tzdata
ENV TZ=Etc/UTC

# Expose port 5000
EXPOSE 5000

# Run the JAR file
ENTRYPOINT ["java","-jar","app.jar"]
