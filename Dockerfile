# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
COPY requirements.txt requirements.txt
RUN apt update && \
    apt install -y pkg-config python3-dev default-libmysqlclient-dev build-essential && \
    pip install -r requirements.txt

# Expose the port Flask is running on
EXPOSE 5002

# Define environment variable for Flask to run in production mode
ENV FLASK_ENV=production

# Command to run the Flask app
CMD ["python", "app.py"]
