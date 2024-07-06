# Use an official Java runtime as a parent image
FROM openjdk:8-jre-slim

# Set the working directory in the container
WORKDIR /app

# Copy the executable JAR file to the working directory
COPY target/polls-0.0.1-SNAPSHOT.jar /app/app.jar

# Copy the application.properties file (if needed, in case it's external)
# COPY src/main/resources/application.properties /app/config/application.properties

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run the JAR file
ENTRYPOINT ["java", "-jar", "app.jar"]
