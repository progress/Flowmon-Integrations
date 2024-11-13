# Microsoft Teams Incoming Webhook script usage

## Teams configuration

Configuration of the Incoming webhook is described at
https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

You only need to select a group and add connector there. This webhook
will provide you with HTTPs URL where the script will send (POST) the
messages.

![This screenshot shows the unique webhook URL.](media/webhook.png)

There is a limitation on how many messages could be sent through the
webhook. The details are available at
<https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using>

Current numbers are four messages in a second and sixty in 30 seconds
and 100 in five minutes. So, this should be deployed really only on the
important event or well configured Flowmon ADS system.

## Flowmon ADS configuration

Details how to configure a custom script are at [User Guide](https://docs.progress.com/bundle/progress-flowmon-ads-12-4/page/topics/user-guide/Custom-Actions.html#custom-scripts) of the Flowmon ADS.

You have two options provide the parameters at the script itself before
uploading

![A screen shot of a configuration lines at the script](media/script-configuration.png)

Or provide these by parameters when after uploading and specifying the
URL and your Flowmon web UI hostname or IP address.

However, with recent update of Webhook functionality the URL got longer then 255 characters
 and that is a limit of parameter value you can use in the UI.
Thus, you must provide the webhook URL in the script for this to work properly. 
The other option would be to use some internal URL shortening but I would not share it with some online one as the URL is sensitive information and anyone with it can use to for posting the data.

    usage: teams-webhook.sh <options>
    Optional:

    --webhook   MS Teams Webhook
    --flowmon   IP / Hostname of Flowmon Web UI for links
    --test      This will send a test message with static text


For example we can create a custom script with those parametres to be different from default.

![New custom scrip configuration](media/new-custom-script.png)

And then configure action where it will allow you to change the parameters.

![New custom scrip action](media/action.png)

You can also test if from any Linux machine when you use parameter test
with some value after it. The output in teams would looks like on image
below.

![A screenshot of a sample message](media/sample-message.png)
