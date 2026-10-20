# Multithreaded TCP Port Scanner

## Introduction

The **Multithreaded TCP Port Scanner** is a Python-based cybersecurity tool designed to identify open TCP ports on a target host. It uses multithreading to perform multiple connection attempts concurrently, improving scanning efficiency compared with a sequential approach.

The project demonstrates fundamental concepts of computer networking, TCP communication, socket programming, and concurrent execution in Python. It also provides configurable scanning parameters and CSV-based reporting, making it useful for learning and conducting basic network assessments on authorized systems.

## Project Overview

The scanner attempts to establish TCP connections to specified ports on a target host and records the outcomes. Users can configure the port range, number of worker threads, and connection timeout through command-line arguments.

The tool displays open ports in the terminal and exports scan results to a CSV file for further analysis.

### Key Features

- **Multithreaded Scanning:** Uses Python's `ThreadPoolExecutor` to execute multiple TCP connection attempts concurrently.
- **Configurable Port Ranges:** Supports scanning an individual port or a specified range of ports.
- **Connection Timeout:** Allows users to configure how long the scanner waits for a connection attempt.
- **Port Status Classification:** Records connection outcomes, including open, closed, timed out or unresponsive, and other connection errors.
- **Common Service Labels:** Associates commonly used port numbers with likely services.
- **CSV Reporting:** Exports scan results, including the target host, port number, status, and service label.
- **Command-Line Interface:** Provides a simple interface for configuring and running scans.

## Technologies Used

- **Programming Language:** Python
- **Networking:** `socket`
- **Concurrency:** `concurrent.futures.ThreadPoolExecutor`
- **Command-Line Arguments:** `argparse`
- **Report Generation:** `csv`

## Project Objective

The primary objective of this project is to understand TCP port scanning, network connection handling, and multithreaded programming while developing a practical command-line utility for basic network reconnaissance.

## Intended Use

This project is intended for educational purposes and authorized network testing. Run scans only against systems you own or have explicit permission to assess.
