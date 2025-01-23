pipeline {
    agent any

    environment {
        MAVEN_HOME = '/usr/share/maven'
        GITHUB_REPO = 'vladdossik/lissa-trading-auth-service'
        DOCKER_IMAGE = 'kenpxrk1/lissa-trading-auth-service'
        DOCKER_TAG = "${env.BUILD_NUMBER}"
        DOCKER_CREDENTIALS_ID = 'kenpxrk1_dockerhub_credentials'
    }

    stages {
        stage('Checkout') {
            steps {
                script {
                    setGitHubCommitStatus('PENDING', 'Pipeline started', 'Checkout code')
                }
                checkout scm
            }
        }

        stage('Build') {
            steps {
                script {
                    setGitHubCommitStatus('PENDING', 'Building project', 'Build stage in progress')
                }
                sh "${MAVEN_HOME}/bin/mvn clean package"
            }
        }

        stage('Test') {
            steps {
                script {
                    setGitHubCommitStatus('PENDING', 'Running tests', 'Test stage in progress')
                }
                sh "${MAVEN_HOME}/bin/mvn test"
            }
        }

        stage('Build and Deploy') {
                    when {
                        branch 'main'
                    }
                    stages {
                        stage('Build Docker Image') {
                            steps {
                                script {
                                    setGitHubCommitStatus('PENDING', 'Building Docker image', 'Docker build in progress')
                                }
                                sh "sudo docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."
                            }
                        }

                        stage('Push Docker Image') {
                            steps {
                                script {
                                    setGitHubCommitStatus('PENDING', 'Pushing Docker image to Docker Hub', 'Docker push in progress')
                                }
                                withCredentials([usernamePassword(credentialsId: DOCKER_CREDENTIALS_ID, usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                                                sh """
                                                echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
                                                """
                                                sh "docker push ${DOCKER_IMAGE}:${DOCKER_TAG}"
                                            }
                            }
                        }

                        stage('Deploy to Kubernetes') {
                            steps {
                                script {
                                    setGitHubCommitStatus('PENDING', 'Deploying to Kubernetes', 'Kubernetes deployment in progress')
                                }
                                sh """
                                kubectl set image deployment/lissa-trading-auth-service \
                                auth-service=${DOCKER_IMAGE}:${DOCKER_TAG} --record
                                """
                            }
                        }
                    }
                }
    }

    post {
        success {
            echo "Deployment successful with version ${DOCKER_TAG}"
        }
        failure {
            echo "Pipeline failed"
        }
        always {
            script {
               def contexts = [
                    'Checkout code',
                    'Build stage in progress',
                    'Test stage in progress',
                    'Docker build in progress',
                    'Docker push in progress',
                    'Kubernetes deployment in progress'
                ]
                contexts.each { context ->
                    setGitHubCommitStatus(currentBuild.result ?: 'SUCCESS', 'Pipeline finished', context)
                }
            }
        }
    }
}

def setGitHubCommitStatus(state, description, context) {
    step([
        $class: 'GitHubCommitStatusSetter',
        reposSource: [$class: 'ManuallyEnteredRepositorySource', url: "https://github.com/${env.GITHUB_REPO}"],
        contextSource: [$class: 'ManuallyEnteredCommitContextSource', context: context],
        statusResultSource: [
            $class: 'ConditionalStatusResultSource',
            results: [
                [$class: 'AnyBuildResult', state: state, message: description]
            ]
        ]
    ])
}