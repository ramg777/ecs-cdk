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


class Pipeline(core.Stack):
    def __init__(self, app: core.App, id: str, props, **kwargs) -> None:
        super().__init__(app, id, **kwargs)

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

        kms_statement3 = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            resources=["*"],
            principals=[aws_iam.ArnPrincipal("arn:aws:iam::245793655931:root")],
            actions=["kms:*"],
        )

        kms_document = aws_iam.PolicyDocument(
            statements=[kms_statement1, kms_statement2, kms_statement3]
        )

        # create a kms key for the S3 bucket
        kms_key = aws_kms.Key(
            self,
            f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-kms_key",
            alias=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            policy=kms_document,
        )

        # pipeline requires versioned bucket
        ci_bucket = aws_s3.Bucket(
            self,
            f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-ci-bucket",
            bucket_name=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-ci-pl-artifact",
            versioned=True,
            encryption_key=kms_key,  # for xacct deployment
            removal_policy=core.RemovalPolicy.DESTROY,
        )

        ecr_mio_mass_env = aws_ecr.Repository.from_repository_arn(
            self,
            f"ecr_mio_mass-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            repository_arn=props["ecr_mass_env_arn"],
        )

        # create local ECR
        ecr = aws_ecr.Repository(
            self,
            f"ecr-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            repository_name=f"ecr-{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            image_scan_on_push=False,
            removal_policy=core.RemovalPolicy.DESTROY,
        )

        # import ecr_remote repo in the remote account
        ecr_remote = aws_ecr.Repository.from_repository_arn(
            self,
            f"ecr-remote-{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}",
            repository_arn=f"arn:aws:ecr:us-east-1:{props['environments'][props['current_env']]['account_number']}:repository/ecr-{props['namespace']}-cd-{props['environments'][props['current_env']]['name']}",
        )

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
                "remote_acccount": aws_codebuild.BuildEnvironmentVariable(
                    value=props["environments"][props["current_env"]]["account_number"]
                ),
            },
            description="Pipeline for CodeBuild push remote",
            timeout=core.Duration.minutes(60),
        )

        # codebuild iam permissions to read write s3
        ci_bucket.grant_read_write(cb_docker_build)

        # create cross account policy statement
        remote_iam_statement = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            resources=[f"{props['environments'][props['current_env']]['cdk_role']}"],
            actions=["sts:AssumeRole"],
        )

        # adding policy statement to docker build
        cb_docker_build.role.add_to_policy(remote_iam_statement)
        cb_docker_build_push_remote.role.add_to_policy(remote_iam_statement)

        # codebuild permissions to interact with ecr
        ecr_mio_mass_env.grant_pull(cb_docker_build)
        ecr.grant_pull_push(cb_docker_build)
        ecr_remote.grant_pull_push(cb_docker_build_push_remote)
        ecr.grant_pull_push(cb_docker_build_push_remote)

        # grant read access to the s3 bucket for the foreign account deployment role
        ci_bucket.grant_read(
            aws_iam.ArnPrincipal(
                f"{props['environments'][props['current_env']]['cdk_role']}"
            )
        )

        # create ssm parameter to get bucket name later
        ci_bucket_param = aws_ssm.StringParameter(
            self,
            f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['name']}-name-param",
            parameter_name=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['account_number']}-{props['environments'][props['current_env']]['name']}",
            string_value=ci_bucket.bucket_name,
            description=f"{props['namespace'].lower()}-{props['environments'][props['current_env']]['account_number']}-{props['environments'][props['current_env']]['name']}-ci_bucket_name",
        )

        # container output
        build_output = aws_codepipeline.Artifact(artifact_name="build")

        # list of code commit repo that will be appended
        code_commit_list = []

        for data in props["environments"][props["current_env"]]["repo_list"]:
            repo = aws_codecommit.Repository.from_repository_name(
                self,
                f"{data['repo_name']}-repo-{props['environments'][props['current_env']]['name']}",
                repository_name=f"{data['repo_name']}",
            )
            # define the s3 artifact
            source_output = aws_codepipeline.Artifact(
                artifact_name=f"{data['repo_name'].replace('-', '_')}_source"
            )

            code_commit_list.append(
                aws_codepipeline_actions.CodeCommitSourceAction(
                    output=source_output,
                    repository=repo,
                    branch=data["branch"],
                    action_name=f"CheckoutDocker{data['repo_name']}",
                    run_order=1,
                    variables_namespace=f"{props['namespace']}_{data['repo_name']}",
                )
            )

        # define container output for hte deploy_remote
        build_output_remote = aws_codepipeline.Artifact(
            artifact_name="build_output_remote"
        )

        # retrieve s3 bucket encryption key created in the remote account, a string value
        remote_bucket_key = aws_kms.Key.from_key_arn(
            self,
            f"{props['remote_namespace']}-SourceBucketKey-{props['environments'][props['current_env']]['name']}",
            #########################////////need to be update per environment////////////////#################################
            key_arn="arn:aws:kms:us-east-1:{props['environments'][props['current_env']]['account_number']}:key/4968aa87-e97e-4525-b9be-a5e5baf72f5b",
        )

        # using the bucket_string_value retrieved above to look up the S3 bucket
        remote_bucket = aws_s3.Bucket.from_bucket_attributes(
            self,
            f"{props['remote_namespace']}-SourceBucket-{props['environments'][props['current_env']]['name']}",
            # account = "409641887510",
            # bucket_name = bucket_string_value,
            account=f"{props['environments'][props['current_env']]['account_number']}",
            #########################////////need to be update per environment////////////////#################################
            # bucket_arn="arn:aws:s3:::dev-inv-mdr-ds-cd-dev",
            bucket_arn=f"arn:aws:s3:::{props['namespace']}-cd-{props['environments'][props['current_env']]['name']}",
            encryption_key=remote_bucket_key,
        )

        # define the pipeline
        pipeline = aws_codepipeline.Pipeline(
            self,
            f"pipeline-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            pipeline_name=f"pl-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            cross_account_keys=True,
            artifact_bucket=ci_bucket,
            stages=[
                aws_codepipeline.StageProps(
                    stage_name="Source", actions=code_commit_list
                ),
                aws_codepipeline.StageProps(
                    stage_name="Build",
                    actions=[
                        aws_codepipeline_actions.CodeBuildAction(
                            action_name="DockerBuildImages",
                            input=code_commit_list[0].action_properties.outputs[0],
                            extra_inputs=list(
                                map(
                                    lambda x: x.action_properties.outputs[0],
                                    code_commit_list[1::],
                                )
                            ),
                            project=cb_docker_build,
                            run_order=1,
                            outputs=[build_output],
                        )
                    ],
                ),
                aws_codepipeline.StageProps(
                    stage_name="BuildPushRemote",
                    actions=[
                        aws_codepipeline_actions.CodeBuildAction(
                            action_name="DockerBuildImagesPushRemote",
                            input=source_output,
                            project=cb_docker_build_push_remote,
                            outputs=[build_output_remote],
                            run_order=1,
                        )
                    ],
                ),
                aws_codepipeline.StageProps(
                    stage_name="deploy",
                    actions=[
                        aws_codepipeline_actions.S3DeployAction(
                            action_name="Deploy",
                            input=build_output_remote,
                            bucket=remote_bucket,
                            role=aws_iam.Role.from_role_arn(
                                self,
                                f"{props['remote_namespace']}-eba_role",
                                role_arn=f"{props['environments'][props['current_env']]['cdk_role']}",
                            ),
                        )
                    ],
                ),
            ],
        )
        # give pipelinerole read write to the bucket
        ci_bucket.grant_read_write(pipeline.role)
        ecr.grant_pull(pipeline.role)

        # pipeline param to get the
        pipeline_param = aws_ssm.StringParameter(
            self,
            f"pl-ssm-param-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            parameter_name=f"{props['namespace']}-pipeline-{props['environments'][props['current_env']]['name']}",
            string_value=pipeline.pipeline_name,
            description="cdk pipeline bucket",
        )

        # cfn output
        core.CfnOutput(
            self,
            f"pl-output-{props['namespace']}-{props['environments'][props['current_env']]['name']}",
            description="Pipeline",
            value=pipeline.pipeline_name,
        )
