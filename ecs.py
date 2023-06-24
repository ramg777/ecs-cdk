from aws_cdk import (
    aws_codepipeline,
    aws_codepipeline_actions,
    aws_codecommit,
    aws_codebuild,
    aws_ssm,
    aws_ecr,
    aws_iam,
    aws_kms,
    aws_s3
)
import aws_cdk as core
​
​
class Pipeline(core.Stack):
    def __init__(self, app: core.App, id: str, props, **kwargs) -> None:
        super().__init__(app, id, **kwargs)
​
        # create kms key policy statement
        kms_statement1 = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            resources=["*"],
            principals=[
                aws_iam.ArnPrincipal(
                    f"{props['environments'][props['current_env']]['cdk_role']}"
                )
            ],
            actions=[
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey",
            ],
        )
​
        kms_statement2 = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            resources=["*"],
            principals=[
                aws_iam.ArnPrincipal(
                    f"{props['environments'][props['current_env']]['cdk_role']}"
                ),
            ],
            actions=[
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant",
            ],
            conditions={"Bool": {"kms:GrantIsForAWSResource": True}},
        )
​
        kms_statement3 = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            resources=["*"],
            principals=[aws_iam.ArnPrincipal("arn:aws:iam::245793655931:root")],
            actions=["kms:*"],
        )
​
        kms_document = aws_iam.PolicyDocument(
            statements=[kms_statement1, kms_statement2, kms_statement3]
        )
​
        # create a kms key for the S3 bucket
        kms_key = aws_kms.Key(
            self,
            f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-kms_key",
            alias=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            policy=kms_document,
        )
​
        # pipeline requires versioned bucket
        ci_bucket = aws_s3.Bucket(
            self,
            f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-ci-bucket",
            bucket_name=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-ci-pl-artifact",
            versioned=True,
            encryption_key=kms_key,  # for xacct deployment
            removal_policy=core.RemovalPolicy.DESTROY,
        )
​
        ecr_mio_mass_env = aws_ecr.Repository.from_repository_arn(
            self,
            f"ecr_mio_mass-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            repository_arn=props["ecr_mass_env_arn"],
        )
​
        # create local ECR
        ecr = aws_ecr.Repository(
            self,
            f"ecr-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            repository_name=f"ecr-{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            image_scan_on_push=False,
            removal_policy=core.RemovalPolicy.DESTROY,
        )
​
        # import ecr_remote repo in the remote account
        ecr_remote = aws_ecr.Repository.from_repository_arn(
            self,
            f"ecr-remote-{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            repository_arn=f"arn:aws:ecr:us-east-1:{props['environments'][props['current_env']]['account_number']}:repository/ecr-{props['namespace']}-cd-{props['environments'][props['current_env']]['name']}",
        )
​
        # codebuild project meant to run in pipeline
        cb_docker_build = aws_codebuild.PipelineProject(
            self,
            f"dockerbuild-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            project_name=f"cb-{props['namespace']}-Docker-Build-{props['environments'][props['current_env']]['name']}",
            build_spec=aws_codebuild.BuildSpec.from_object(
                dict(
                    version="0.2",
                    phases={
                        "install": {"nodejs": 10.16},
                        "pre_build": {
                            "commands": [
                                "echo logging into docker",
                                "$(aws ecr get-login --no-include-email --region $AWS_DEFAULT_REGION)",
                                "env",
                                "export tag=${CODEBUILD_RESOLVED_SOURCE_VERSION}",
                                "mv $CODEBUILD_SRC_DIR_cs_shared_csmass_source ./mass",
                            ]
                        },
                        "build": {
                            "commands": [
                                "echo Entered the build phase...",
                                "docker build -t ${tag}:latest .",
                                "export Id=`docker inspect --format='{{.Id}}' ${tag}:latest | cut -d ':' -f2`",
                                "docker tag $tag:latest $ecr:$Id",
                                "docker tag $tag:latest $ecr:ci-$Id",
                                "docker tag $tag:latest $ecr:$ecr_image_env",
                                "docker push $ecr:$Id",
                                "docker push $ecr:ci-$Id",
                                "docker push $ecr:$ecr_image_env",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                'echo "In Post-Build Stage"',
                                'printf \'[{"name":"%s","imageUri":"%s"}]\' $ecs_container_name $ecr:$Id > imagedefinitions.json',
                                "pwd; ls -al; cat imagedefinitions.json",
                            ]
                        },
                    },
                    artifacts={"files": ["imagedefinitions.json"]},
                )
            ),
            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                "ecr": aws_codebuild.BuildEnvironmentVariable(value=ecr.repository_uri),
                "ecr_image_env": aws_codebuild.BuildEnvironmentVariable(
                    value=props["current_env"]
                ),
                "ecs_container_name": aws_codebuild.BuildEnvironmentVariable(
                    value=props["namespace"]
                ),
            },
            description="Pipeline for CodeBuild",
            timeout=core.Duration.minutes(60),
        )
​
        # codebuild project meant to run in the pipeline - push image to the remote ECR repo
        cb_docker_build_push_remote = aws_codebuild.PipelineProject(
            self,
            f"DockerBuildPushRemote-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            project_name=f"cb-{props['namespace']}-Docker-Build-Push-Remote-{props['environments'][props['current_env']]['name']}",
            build_spec=aws_codebuild.BuildSpec.from_object(
                dict(
                    version="0.2",
                    phases={
                        "pre_build": {
                            "commands": [
                                "echo logging into docker",
                                "$(aws ecr get-login --no-include-email --region us-east-1)",
                                "export tag=${CODEBUILD_RESOLVED_SOURCE_VERSION}",
                                "env",
                            ]
                        },
                        "build": {
                            "commands": [
                                "echo Entered the post_build phase...",
                                "echo docker pull completed on `date`",
                                "docker pull $ecr:$ecr_image_env",
                                "export Id=`docker inspect --format='{{.Id}}' $ecr:$ecr_image_env | cut -d ':' -f2`",
                                "docker tag $ecr:$ecr_image_env $ecr_remote:$Id",
                                "docker tag $ecr:$ecr_image_env $ecr_remote:ci-$Id",
                                "docker tag $ecr:$ecr_image_env $ecr_remote:$ecr_image_env",
                                ### push to the ecr_remote
                                'ASSUME_ROLE_ARN="arn:aws:iam::${remote_acccount}:role/eba-role"',
                                "TEMP_ROLE=$(aws sts assume-role --role-arn $ASSUME_ROLE_ARN --role-session-name eba)",
                                "export TEMP_ROLE",
                                "export AWS_ACCESS_KEY_ID=$(echo \"${TEMP_ROLE}\" | jq -r '.Credentials.AccessKeyId')",
                                "export AWS_SECRET_ACCESS_KEY=$(echo \"${TEMP_ROLE}\" | jq -r '.Credentials.SecretAccessKey')",
                                "export AWS_SESSION_TOKEN=$(echo \"${TEMP_ROLE}\" | jq -r '.Credentials.SessionToken')",
                                #########################////////need to be update per environment////////////////#################################
                                "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ${remote_acccount}.dkr.ecr.us-east-1.amazonaws.com",
                                "docker push $ecr_remote:$Id",
                                "docker push $ecr_remote:ci-$Id",
                                "docker push $ecr_remote:$ecr_image_env",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                'echo "In Post-Build Stage"',
                                #########################////////need to be update per application ////////////////#################################
                                'printf \'[{"name":"%s","imageUri":"%s"}]\' $ecs_container_name $ecr_remote:$Id > imagedefinitions.json',
                                "pwd; ls -al; cat imagedefinitions.json",
                                "zip imagedefinitions.zip imagedefinitions.json",
                                "pwd; ls -lah",
                                "find . -name imagedefinitions.zip",
                            ]
                        },
                    },
                    artifacts={"files": ["imagedefinitions.zip"]},
                )
            ),
            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
            ),
            # pass the ecr repo uri into the codebuild project so codebuild knows where to push
            environment_variables={
                "ecr": aws_codebuild.BuildEnvironmentVariable(value=ecr.repository_uri),
                ### mssing for the ecr_remote
                "ecr_remote": aws_codebuild.BuildEnvironmentVariable(
                    value=ecr_remote.repository_uri
                ),
                "ecs_container_name": aws_codebuild.BuildEnvironmentVariable(
                    value=props["namespace"]
                ),
                "ecr_image_env": aws_codebuild.BuildEnvironmentVariable(
                    value=props["current_env"]
                ),
                "remote_acccount": aws_codebuild.BuildEnvironm...
