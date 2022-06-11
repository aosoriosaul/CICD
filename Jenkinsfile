node {
    properties([
        parameters([
            text(name: 'projectId', defaultValue: '2808', description: 'Identificador de proyecto en gitlab'),
            booleanParam(defaultValue: true, description: 'LimpiarWorkspace', name: 'LimpiarWorkspace'),
            booleanParam(name: 'keepNode', defaultValue: false, description: 'Conserva la carpeta node')
        ])
    ])

    deleteDir()
    
    sh '/usr/local/git/bin/git clone git@10.63.32.231:cicd/jenkins/pipeline/jenkinsfile.git'
    
    def rootDirectory = pwd()
    def jenkinsfile =  load "${rootDirectory}/jenkinsfile/jenkinsfilemaster.groovy"
    jenkinsfile.mainFlow()
}  
  